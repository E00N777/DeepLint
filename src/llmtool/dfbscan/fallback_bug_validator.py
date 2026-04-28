import json
from typing import Dict, List, Optional, Sequence

from agent.memory_agent import MemoryAgent
from llmtool.LLM_tool import *
from llmtool.LLM_utils import *
from llmtool.dfbscan.uaf_semantic_summaries import build_uaf_semantic_summary
from memory.syntactic.function import *
from memory.syntactic.value import *

BASE_PATH = Path(__file__).resolve().parent.parent.parent


class FallbackBugValidatorInput(LLMToolInput):
    def __init__(
        self,
        bug_type: str,
        source_value: Value,
        source_function: Function,
        candidate_functions: Sequence[Function],
        observed_values: Dict[int, Sequence[Value]],
        trigger_reasons: Sequence[str],
    ) -> None:
        self.bug_type = bug_type
        self.source_value = source_value
        self.source_function = source_function
        self.candidate_functions = list(candidate_functions)
        self.observed_values = {
            function_id: list(values) for function_id, values in observed_values.items()
        }
        self.trigger_reasons = list(trigger_reasons)
        return

    def __hash__(self) -> int:
        observed_items = tuple(
            sorted(
                (
                    function_id,
                    tuple(sorted(str(value) for value in values)),
                )
                for function_id, values in self.observed_values.items()
            )
        )
        candidate_function_ids = tuple(
            function.function_id for function in self.candidate_functions
        )
        return hash(
            (
                self.bug_type,
                str(self.source_value),
                self.source_function.function_id,
                candidate_function_ids,
                observed_items,
                tuple(self.trigger_reasons),
            )
        )


class FallbackBugValidatorOutput(LLMToolOutput):
    def __init__(
        self,
        is_reachable: bool,
        explanation_str: str,
        sink_value: Optional[Value] = None,
        sink_function: Optional[Function] = None,
        path_summary: str = "",
    ) -> None:
        self.is_reachable = is_reachable
        self.explanation_str = explanation_str
        self.sink_value = sink_value
        self.sink_function = sink_function
        self.path_summary = path_summary
        return

    def __str__(self) -> str:
        return (
            f"Is reachable: {self.is_reachable}\n"
            f"Sink value: {self.sink_value}\n"
            f"Path: {self.path_summary}\n"
            f"Explanation: {self.explanation_str}"
        )


class FallbackBugValidator(LLMTool):
    def __init__(
        self,
        model_name: str,
        temperature: float,
        language: str,
        max_query_num: int,
        logger: Logger,
        memory_agent: Optional[MemoryAgent] = None,
    ) -> None:
        super().__init__(model_name, temperature, language, max_query_num, logger)
        self.prompt_file = (
            f"{BASE_PATH}/prompt/{language}/dfbscan/fallback_bug_validator.json"
        )
        self.memory_agent = memory_agent
        return

    def _get_prompt(self, input: LLMToolInput) -> str:
        if not isinstance(input, FallbackBugValidatorInput):
            raise TypeError("expect FallbackBugValidatorInput")
        with open(self.prompt_file, "r") as f:
            prompt_template_dict = json.load(f)

        prompt = prompt_template_dict["task"]
        prompt += "\n" + "\n".join(prompt_template_dict["analysis_rules_common"])
        bug_rules = prompt_template_dict["analysis_rules_by_type"].get(
            input.bug_type, []
        )
        prompt += "\n" + "\n".join(bug_rules)
        prompt += "\n" + "\n".join(prompt_template_dict["answer_format"])
        prompt += "\n" + "".join(prompt_template_dict["meta_prompts"])

        trigger_str = "\n".join(f"- {reason}" for reason in input.trigger_reasons)
        prompt = prompt.replace("<BUG_TYPE>", input.bug_type)
        prompt = prompt.replace(
            "<SOURCE>",
            (
                f"{input.source_value.name} at absolute line "
                f"{input.source_value.line_number} in function "
                f"{input.source_function.function_name}"
            ),
        )
        prompt = prompt.replace("<TRIGGER_REASONS>", trigger_str or "- none")

        observed_blocks = []
        context_lines = []
        for index, function in enumerate(input.candidate_functions, start=1):
            observed_values = sorted(
                input.observed_values.get(function.function_id, []),
                key=lambda value: (value.line_number, value.name, value.index),
            )
            observed_str = (
                "\n".join(
                    f"- {value.name} at absolute line {value.line_number} ({value.label})"
                    for value in observed_values
                )
                if observed_values
                else "- none"
            )
            context_lines.append(
                f"- ContextId {index}: {function.function_name} [{function.file_path}] "
                f"lines {function.start_line_number}-{function.end_line_number}"
            )
            observed_blocks.append(
                "\n".join(
                    [
                        f"[ContextId {index}] Function: {function.function_name}",
                        f"File: {function.file_path}",
                        "Observed propagation hints:",
                        observed_str,
                        "Code:",
                        "```",
                        function.attach_absolute_line_number(),
                        "```",
                    ]
                )
            )

        prompt = prompt.replace("<FUNCTION_INDEX>", "\n".join(context_lines))
        prompt = prompt.replace("<FUNCTION_CONTEXTS>", "\n\n".join(observed_blocks))

        if input.bug_type == "UAF":
            summary_str = build_uaf_semantic_summary(input.candidate_functions)
            if summary_str:
                prompt += "\n" + summary_str

        if self.memory_agent is not None:
            values_to_functions = {
                input.source_value: input.source_function,
            }
            for function in input.candidate_functions:
                for value in input.observed_values.get(function.function_id, []):
                    values_to_functions[value] = function
            memory_str = self.memory_agent.get_path_memory(
                input.bug_type, values_to_functions
            )
            prompt += "\nRelevant memory:\n" + memory_str

        return prompt

    def _parse_response(
        self, response: str, input: Optional[LLMToolInput] = None
    ) -> Optional[LLMToolOutput]:
        answer_matches = re.findall(
            r"Answer:\s*\**\s*(Yes|No)\b", response, re.IGNORECASE
        )
        if not answer_matches:
            self.logger.print_log("Answer not found in fallback output")
            return None

        answer = answer_matches[-1].strip().lower()
        path_match = re.findall(r"Path:\s*(.+)", response)
        reason_match = re.findall(r"Reason:\s*(.+)", response)
        explanation = reason_match[-1].strip() if reason_match else response.strip()
        path_summary = path_match[-1].strip() if path_match else ""

        if answer != "yes":
            output = FallbackBugValidatorOutput(False, explanation, path_summary=path_summary)
            self.logger.print_log("Output of fallback_bug_validator:\n", str(output))
            return output

        if not isinstance(input, FallbackBugValidatorInput):
            raise TypeError("expect FallbackBugValidatorInput")

        context_match = re.findall(r"ContextId:\s*(\d+)", response, re.IGNORECASE)
        sink_match = re.findall(r"Sink:\s*(.+)", response)
        line_match = re.findall(r"Line:\s*(\d+)", response)

        if not context_match or not sink_match or not line_match:
            self.logger.print_log("Fallback Yes output is missing sink metadata")
            return None

        context_index = int(context_match[-1]) - 1
        if context_index < 0 or context_index >= len(input.candidate_functions):
            self.logger.print_log("Fallback returned invalid ContextId")
            return None

        sink_function = input.candidate_functions[context_index]
        sink_line_number = int(line_match[-1])
        if (
            sink_line_number < sink_function.start_line_number
            or sink_line_number > sink_function.end_line_number
        ):
            self.logger.print_log("Fallback returned sink line outside function range")
            return None

        sink_value = Value(
            sink_match[-1].strip(),
            sink_line_number,
            ValueLabel.SINK,
            sink_function.file_path,
        )
        output = FallbackBugValidatorOutput(
            True,
            explanation,
            sink_value=sink_value,
            sink_function=sink_function,
            path_summary=path_summary,
        )
        self.logger.print_log("Output of fallback_bug_validator:\n", str(output))
        return output
