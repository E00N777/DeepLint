from memory.syntactic.function import *
from memory.syntactic.value import *
from typing import Dict


class BugReport:
    def __init__(
        self,
        bug_type: str,
        buggy_value: Value,
        relevant_functions: Dict[int, Function],
        explanation: str,
        source_value: Value | None = None,
        buggy_path: list[Value] | None = None,
        is_human_confirmed_true: bool = False,
        detection_mode: str = "strict",
        report_confidence: str = "high",
    ) -> None:
        """
        :param bug_type: the bug type
        :param buggy_value: the buggy value
        :param relevant_functions: the relevant functions
        :param explanation: the explanation
        """
        self.bug_type = bug_type
        self.buggy_value = buggy_value
        self.relevant_functions = relevant_functions
        self.explanation = explanation
        self.source_value = source_value
        self.buggy_path = buggy_path or []
        self.is_human_confirmed_true = is_human_confirmed_true
        self.detection_mode = detection_mode
        self.report_confidence = report_confidence
        return

    def to_dict(self) -> dict:
        return {
            "bug_type": self.bug_type,
            "buggy_value": str(self.buggy_value),
            "source_value": (
                str(self.source_value) if self.source_value is not None else None
            ),
            "buggy_path": [str(value) for value in self.buggy_path],
            "relevant_functions": [
                [
                    self.relevant_functions[function_id].file_path
                    for function_id in self.relevant_functions
                ],
                [
                    self.relevant_functions[function_id].function_name
                    for function_id in self.relevant_functions
                ],
                [
                    self.relevant_functions[function_id].function_code
                    for function_id in self.relevant_functions
                ],
            ],
            "explanation": self.explanation,
            "detection_mode": self.detection_mode,
            "report_confidence": self.report_confidence,
            "is_human_confirmed_true": (
                str(self.is_human_confirmed_true)
                if self.is_human_confirmed_true is not None
                else "unknown"
            ),
        }

    def __str__(self):
        return str(self.to_dict())

    def __hash__(self) -> int:
        relevant_functions_ids = [
            function.function_id for function in self.relevant_functions.values()
        ]
        return hash(
            (
                self.buggy_value,
                self.source_value,
                tuple(sorted(relevant_functions_ids)),
            )
        )

    def __eq__(self, value: object) -> bool:
        if not isinstance(value, BugReport):
            return False
        return hash(self) == hash(value)
