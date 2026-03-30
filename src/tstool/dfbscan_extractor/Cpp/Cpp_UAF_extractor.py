import re
from typing import List, Optional
import tree_sitter

from tstool.analyzer.TS_analyzer import *
from tstool.analyzer.Cpp_TS_analyzer import *
from ..dfbscan_extractor import *


class Cpp_UAF_Extractor(DFBScanExtractor):
    """
    UAF extraction for C/C++.

    The key design choice is that a UAF source is the released object
    expression itself, not the whole deallocation statement. For example:

      free(ptr)        -> source: ptr
      delete p         -> source: p
      delete [] items  -> source: items

    This keeps the later propagation analysis focused on the object whose
    lifetime ended, instead of the free/delete statement syntax.
    """

    FREE_FUNCTIONS = {"free", "ngx_destroy_black_list_link"}
    UAF_SINK_NODE_TYPES = (
        "pointer_expression",
        "field_expression",
        "subscript_expression",
    )

    def _node_text(self, source_code: str | bytes, node: tree_sitter.Node) -> str:
        return get_node_text(source_code, node)

    def _line_number(self, _source_code: str | bytes, node: tree_sitter.Node) -> int:
        return get_node_start_line(node)

    def _strip_wrapping_parentheses(self, expr: str) -> str:
        expr = expr.strip()
        while expr.startswith("(") and expr.endswith(")"):
            depth = 0
            balanced = True
            for index, ch in enumerate(expr):
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                    if depth == 0 and index != len(expr) - 1:
                        balanced = False
                        break
            if not balanced or depth != 0:
                break
            expr = expr[1:-1].strip()
        return expr

    def _normalize_expr(self, expr: str) -> str:
        expr = re.sub(r"\s+", "", expr)
        return self._strip_wrapping_parentheses(expr)

    def _unwrap_source_expr(self, node: tree_sitter.Node) -> tree_sitter.Node:
        """
        Peel off syntax wrappers that do not change the released object identity,
        such as casts and parentheses.
        """
        current = node
        while current.type in {"parenthesized_expression", "cast_expression"}:
            named_children = list(current.named_children)
            if not named_children:
                break
            current = named_children[-1]
        return current

    def _is_free_call(self, node: tree_sitter.Node, source_code: str | bytes) -> bool:
        if node.type != "call_expression":
            return False
        for child in node.children:
            if child.type == "identifier":
                name = self._node_text(source_code, child)
                return name in self.FREE_FUNCTIONS
        return False

    def _release_target_node(
        self, node: tree_sitter.Node, source_code: str | bytes
    ) -> Optional[tree_sitter.Node]:
        if node.type == "delete_expression":
            named_children = list(node.named_children)
            if not named_children:
                return None
            return self._unwrap_source_expr(named_children[-1])

        if not self._is_free_call(node, source_code):
            return None

        for child in node.children:
            if child.type != "argument_list":
                continue
            named_children = list(child.named_children)
            if not named_children:
                return None
            return self._unwrap_source_expr(named_children[0])
        return None

    def _iter_release_nodes(self, root_node: tree_sitter.Node) -> List[tree_sitter.Node]:
        nodes = find_nodes_by_type(root_node, "call_expression")
        nodes.extend(find_nodes_by_type(root_node, "delete_expression"))
        return nodes

    def _find_release_node(
        self,
        root_node: tree_sitter.Node,
        source_code: str | bytes,
        released_value: Value,
    ) -> Optional[tree_sitter.Node]:
        released_expr = self._normalize_expr(released_value.name)
        for node in sorted(self._iter_release_nodes(root_node), key=lambda n: n.start_byte):
            target_node = self._release_target_node(node, source_code)
            if target_node is None:
                continue
            if self._line_number(source_code, target_node) != released_value.line_number:
                continue
            if self._normalize_expr(self._node_text(source_code, target_node)) == released_expr:
                return node
        return None

    def _candidate_sink_nodes(
        self, root_node: tree_sitter.Node
    ) -> List[tree_sitter.Node]:
        nodes: List[tree_sitter.Node] = []
        for node_type in self.UAF_SINK_NODE_TYPES:
            nodes.extend(find_nodes_by_type(root_node, node_type))
        return nodes

    def _assignment_nodes(self, root_node: tree_sitter.Node) -> List[tree_sitter.Node]:
        nodes = find_nodes_by_type(root_node, "assignment_expression")
        nodes.extend(find_nodes_by_type(root_node, "init_declarator"))
        return sorted(nodes, key=lambda n: n.start_byte)

    def _extract_declared_name(
        self, declarator_node: tree_sitter.Node, source_code: str | bytes
    ) -> str:
        identifiers = find_nodes_by_type(declarator_node, "identifier")
        if identifiers:
            return self._node_text(source_code, identifiers[-1])
        field_identifiers = find_nodes_by_type(declarator_node, "field_identifier")
        if field_identifiers:
            return self._node_text(source_code, field_identifiers[-1])
        return self._node_text(source_code, declarator_node)

    def _extract_assignment_event(
        self, node: tree_sitter.Node, source_code: str | bytes
    ) -> Optional[tuple[int, int, str, str]]:
        named_children = list(node.named_children)
        if node.type == "assignment_expression":
            if len(named_children) < 2:
                return None
            lhs = self._node_text(source_code, named_children[0])
            rhs = self._node_text(source_code, named_children[-1])
        elif node.type == "init_declarator":
            if len(named_children) < 2:
                return None
            lhs = self._extract_declared_name(named_children[0], source_code)
            rhs = self._node_text(source_code, named_children[-1])
        else:
            return None

        return (
            node.start_byte,
            self._line_number(source_code, node),
            self._normalize_expr(lhs),
            self._normalize_expr(rhs),
        )

    def _is_live_alias_expr(self, expr: str, live_aliases: set[str]) -> bool:
        expr = self._normalize_expr(expr)
        if not expr:
            return False
        if expr in live_aliases:
            return True
        return any(
            expr.startswith(alias + suffix)
            for alias in live_aliases
            for suffix in ("->", ".", "[")
        )

    def _apply_assignment_to_aliases(
        self, live_aliases: set[str], lhs: str, rhs: str
    ) -> None:
        lhs = self._normalize_expr(lhs)
        rhs = self._normalize_expr(rhs)
        if not lhs:
            return

        rhs_is_alias = self._is_live_alias_expr(rhs, live_aliases)

        if lhs in live_aliases and not rhs_is_alias:
            live_aliases.discard(lhs)
        elif rhs_is_alias:
            live_aliases.add(lhs)

    def _build_live_aliases_at_release(
        self,
        root_node: tree_sitter.Node,
        source_code: str | bytes,
        release_node: tree_sitter.Node,
        released_expr: str,
    ) -> set[str]:
        released_alias = self._normalize_expr(released_expr)
        if not released_alias:
            return set()

        # Track aliases that are definitely live at the release point.
        live_aliases = {released_alias}

        # Track which aliases can still explain earlier copy assignments when
        # we walk backwards from the release point.
        backward_trace_aliases = {released_alias}

        # A later non-alias assignment kills any earlier alias copies into the
        # same lhs, so block them when scanning backwards.
        killed_alias_targets: set[str] = set()

        for node in reversed(self._assignment_nodes(root_node)):
            if node.start_byte >= release_node.start_byte:
                continue

            event = self._extract_assignment_event(node, source_code)
            if event is None:
                continue

            _, _, lhs, rhs = event
            if not lhs:
                continue

            rhs_is_alias = self._is_live_alias_expr(rhs, backward_trace_aliases)
            lhs_is_trace_alias = lhs in backward_trace_aliases

            if lhs != released_alias and not rhs_is_alias:
                killed_alias_targets.add(lhs)

            if lhs_is_trace_alias and not rhs_is_alias:
                backward_trace_aliases.discard(lhs)

            if rhs_is_alias and lhs not in killed_alias_targets:
                live_aliases.add(lhs)
                backward_trace_aliases.add(lhs)

        return live_aliases

    def _matches_released_object(
        self, node: tree_sitter.Node, source_code: str | bytes, live_aliases: set[str]
    ) -> bool:
        if not live_aliases:
            return False

        node_text = self._normalize_expr(self._node_text(source_code, node))

        if node.type == "pointer_expression":
            named_children = list(node.named_children)
            if not named_children:
                return False
            operand = self._normalize_expr(self._node_text(source_code, named_children[-1]))
            return operand in live_aliases

        if node.type in {"field_expression", "subscript_expression"}:
            named_children = list(node.named_children)
            if not named_children:
                return False

            base_text = self._normalize_expr(self._node_text(source_code, named_children[0]))
            if base_text in live_aliases:
                return True

            return any(
                node_text.startswith(alias + suffix)
                for alias in live_aliases
                for suffix in ("->", ".", "[")
            )

        return False

    def extract_sources(self, function: Function) -> List[Value]:
        root_node = function.parse_tree_root_node
        source_code = self.ts_analyzer.code_in_files[function.file_path]
        source_bytes = to_source_bytes(source_code)
        file_path = function.file_path

        sources: List[Value] = []
        for node in self._iter_release_nodes(root_node):
            target_node = self._release_target_node(node, source_bytes)
            if target_node is None:
                continue

            target_name = self._node_text(source_bytes, target_node).strip()
            if not target_name:
                continue

            sources.append(
                Value(
                    target_name,
                    self._line_number(source_bytes, target_node),
                    ValueLabel.SRC,
                    file_path,
                )
            )
        return sources

    def extract_sinks(self, function: Function) -> List[Value]:
        """
        Return generic candidate UAF use sites. The source-specific filtering is
        done by extract_relevant_sinks().
        """
        root_node = function.parse_tree_root_node
        source_code = self.ts_analyzer.code_in_files[function.file_path]
        source_bytes = to_source_bytes(source_code)
        file_path = function.file_path

        sinks: List[Value] = []
        for node in self._candidate_sink_nodes(root_node):
            if node.type == "pointer_expression" and node.children[0].type != "*":
                continue
            sinks.append(
                Value(
                    self._node_text(source_bytes, node),
                    self._line_number(source_bytes, node),
                    ValueLabel.SINK,
                    file_path,
                )
            )
        return sinks

    def extract_relevant_sinks(
        self, function: Function, released_value: Value
    ) -> List[Value]:
        """
        Return only post-release use sites that syntactically match the released
        object or one of its direct derived access expressions in the same
        function.
        """
        root_node = function.parse_tree_root_node
        source_code = self.ts_analyzer.code_in_files[function.file_path]
        source_bytes = to_source_bytes(source_code)
        file_path = function.file_path
        release_node = self._find_release_node(root_node, source_bytes, released_value)
        if release_node is None:
            return []

        live_aliases = self._build_live_aliases_at_release(
            root_node, source_bytes, release_node, released_value.name
        )

        sinks: List[Value] = []
        events: List[tuple[int, str, tree_sitter.Node]] = []
        for node in self._assignment_nodes(root_node):
            if node.start_byte > release_node.start_byte:
                events.append((node.start_byte, "assign", node))
        for node in self._candidate_sink_nodes(root_node):
            if node.type == "pointer_expression" and node.children[0].type != "*":
                continue
            if node.start_byte > release_node.start_byte:
                events.append((node.start_byte, "sink", node))

        events.sort(key=lambda item: item[0])

        for _, event_type, node in events:
            if event_type == "assign":
                event = self._extract_assignment_event(node, source_bytes)
                if event is None:
                    continue
                _, _, lhs, rhs = event
                self._apply_assignment_to_aliases(live_aliases, lhs, rhs)
                continue

            if not self._matches_released_object(node, source_bytes, live_aliases):
                continue

            sinks.append(
                Value(
                    self._node_text(source_bytes, node),
                    self._line_number(source_bytes, node),
                    ValueLabel.SINK,
                    file_path,
                )
            )
        return sinks
