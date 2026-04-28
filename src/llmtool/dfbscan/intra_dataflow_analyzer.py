from os import path
import json
import time
from typing import List, Set, Optional, Dict
from llmtool.LLM_utils import *
from llmtool.LLM_tool import *
from memory.syntactic.function import *
from memory.syntactic.value import *
from memory.syntactic.api import *
from agent.memory_agent import MemoryAgent

BASE_PATH = Path(__file__).resolve().parent.parent.parent


class IntraDataFlowAnalyzerInput(LLMToolInput):
    def __init__(
        self,
        function: Function,
        summary_start: Value,
        sink_values: List[Tuple[str, int]],
        call_statements: List[Tuple[str, int]],
        ret_values: List[Tuple[str, int]],
    ) -> None:
        self.function = function
        self.summary_start = summary_start
        self.sink_values = sink_values
        self.call_statements = call_statements
        self.ret_values = ret_values
        return

    def __hash__(self) -> int:
        return hash((self.function.function_id, str(self.summary_start)))


class IntraDataFlowAnalyzerOutput(LLMToolOutput):
    def __init__(
        self,
        reachable_values: List[Set[Value]],
        raw_response: str = "",
        response_mentions_sink: bool = False,
        parsed_sink_count: int = 0,
    ) -> None:
        self.reachable_values = reachable_values
        self.raw_response = raw_response
        self.response_mentions_sink = response_mentions_sink
        self.parsed_sink_count = parsed_sink_count
        return

    def __str__(self):
        output_str = ""
        for i, reachable_values_per_path in enumerate(self.reachable_values):
            output_str += f"Path {i}:\n"
            for value in reachable_values_per_path:
                output_str += f"- {value}\n"
        return output_str


class IntraDataFlowAnalyzer(LLMTool):
    def __init__(
        self,
        model_name: str,
        temperature: float,
        language: str,
        max_query_num: int,
        logger: Logger,
        memory_agent: Optional[MemoryAgent] = None,
    ) -> None:
        """
        :param model_name: the model name
        :param temperature: the temperature
        :param language: the programming language
        :param max_query_num: the maximum number of queries if the model fails
        :param logger: the logger
        """
        super().__init__(model_name, temperature, language, max_query_num, logger)
        self.prompt_file = (
            f"{BASE_PATH}/prompt/{language}/dfbscan/intra_dataflow_analyzer.json"
        )
        self.memory_agent = memory_agent
        return

    def _get_prompt(self, input: LLMToolInput) -> str:
        if not isinstance(input, IntraDataFlowAnalyzerInput):
            raise TypeError("Expect IntraDataFlowAnalyzerInput")
        with open(self.prompt_file, "r") as f:
            prompt_template_dict = json.load(f)
        prompt = prompt_template_dict["task"]
        prompt += "\n" + "\n".join(prompt_template_dict["analysis_rules"])
        prompt += "\n" + "\n".join(prompt_template_dict["analysis_examples"])
        prompt += "\n" + "".join(prompt_template_dict["meta_prompts"])
        prompt = prompt.replace(
            "<ANSWER>", "\n".join(prompt_template_dict["answer_format_cot"])
        )
        prompt = prompt.replace("<QUESTION>", prompt_template_dict["question_template"])

        function_context = input.function.lined_code
        if self.memory_agent is not None:
            function_context = self.memory_agent.build_intra_function_context(
                input.function,
                input.summary_start,
                input.sink_values,
                input.call_statements,
                input.ret_values,
            )

        prompt = (
            prompt.replace("<FUNCTION>", function_context)
            .replace("<SRC_NAME>", input.summary_start.name)
            .replace(
                "<SRC_LINE>",
                str(
                    input.summary_start.line_number
                    - input.function.start_line_number
                    + 1
                ),
            )
        )

        sinks_str = "Sink values in this function:\n"
        for sink_value in input.sink_values:
            sinks_str += f"- {sink_value[0]} at line {sink_value[1]}\n"
        prompt = prompt.replace("<SINK_VALUES>", sinks_str)

        calls_str = "Call statements in this function:\n"
        for call_statement in input.call_statements:
            calls_str += f"- {call_statement[0]} at line {call_statement[1]}\n"
        prompt = prompt.replace("<CALL_STATEMENTS>", calls_str)

        rets_str = "Return values in this function:\n"
        for ret_val in input.ret_values:
            rets_str += f"- {ret_val[0]} at line {ret_val[1]}\n"
        prompt = prompt.replace("<RETURN_VALUES>", rets_str)

        if self.memory_agent is not None:
            memory_str = self.memory_agent.get_intra_memory(
                input.function,
                input.summary_start,
                input.sink_values,
                input.call_statements,
                input.ret_values,
            )
            prompt += "\nRelevant memory:\n" + memory_str
        return prompt

    def _parse_response(
        self, response: str, input: Optional[LLMToolInput] = None
    ) -> Optional[LLMToolOutput]:
        """
        Parse the LLM response to extract all execution paths and their propagation details.

        Args:
            response (str): The response string from the LLM.
            input (IntraDataFlowAnalyzerInput): The input object containing function details.

        Returns:
            IntraDataFlowAnalyzerOutput: The output containing reachable values for each path.
        """
        paths: List[Dict] = []

        path_header_re = re.compile(r"Path\s*(\d+):\s*([^;]+);?$")
        detail_re = re.compile(
            r"Type:\s*([^;]+);\s*"
            r"Name:\s*([^;]+);\s*"
            r"Function:\s*([^;]+);\s*"
            r"Index:\s*([^;]+);\s*"
            r"Line:\s*([^;]+);"
        )

        answer_idx = response.find("Answer:")
        answer_section = response[answer_idx:] if answer_idx != -1 else response
        response_mentions_sink = (
            re.search(r"\bsink\b", answer_section, re.IGNORECASE) is not None
        )

        current_path = None
        for line in answer_section.splitlines():
            line = line.strip().lstrip("-").strip()
            if not line:
                continue

            header_match = path_header_re.match(line)
            if header_match:
                if current_path:
                    paths.append(current_path)
                current_path = {
                    "path_number": header_match.group(1).strip(),
                    "execution_path": header_match.group(2).strip(),
                    "propagation_details": [],
                }
            elif current_path is not None:
                detail_match = detail_re.match(line)
                if detail_match:
                    detail = {
                        "type": detail_match.group(1).strip(),
                        "name": detail_match.group(2).strip(),
                        "function": detail_match.group(3).strip(),
                        "index": detail_match.group(4).strip(),
                        "line": detail_match.group(5).strip(),
                    }
                    current_path["propagation_details"].append(detail)

        if current_path:
            paths.append(current_path)

        assert input is not None, "input cannot be none"
        if not isinstance(input, IntraDataFlowAnalyzerInput):
            raise TypeError("Expect IntraDataFlowAnalyzerInput")

        # Process paths to extract reachable values
        reachable_values = []
        file_path = input.function.file_path
        start_line_number = input.function.start_line_number
        parsed_sink_count = 0

        for single_path in paths:
            reachable_values_per_path = set()
            for detail in single_path["propagation_details"]:
                if not detail["line"].isdigit():
                    continue
                line_number = int(detail["line"]) + start_line_number - 1
                if detail["type"] == "Argument":
                    reachable_values_per_path.add(
                        Value(
                            detail["name"],
                            line_number,
                            ValueLabel.ARG,
                            file_path,
                            int(detail["index"]),
                        )
                    )
                elif detail["type"] == "Parameter":
                    reachable_values_per_path.add(
                        Value(
                            detail["name"],
                            line_number,
                            ValueLabel.PARA,
                            file_path,
                            int(detail["index"]),
                        )
                    )
                elif detail["type"] == "Return":
                    reachable_values_per_path.add(
                        Value(
                            detail["name"],
                            line_number,
                            ValueLabel.RET,
                            file_path,
                            int(detail["index"]),
                        )
                    )
                elif detail["type"] == "Sink":
                    parsed_sink_count += 1
                    reachable_values_per_path.add(
                        Value(detail["name"], line_number, ValueLabel.SINK, file_path)
                    )
            reachable_values.append(reachable_values_per_path)

        output = IntraDataFlowAnalyzerOutput(
            reachable_values,
            response,
            response_mentions_sink,
            parsed_sink_count,
        )
        if self.memory_agent is not None:
            self.memory_agent.record_intra_result(
                input.function, input.summary_start, output.reachable_values
            )
        self.logger.print_log(
            "Output of intra-procedural data-flow analyzer:", output.reachable_values
        )
        return output
