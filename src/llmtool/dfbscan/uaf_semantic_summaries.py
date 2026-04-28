import re
from typing import Iterable, List

from memory.syntactic.function import Function


COMMON_UAF_API_SUMMARIES = {
    "SNMP_FREE": "Frees the pointed heap object and writes NULL back to the same lvalue. A later use of that variable requires a re-assignment first.",
    "SNMP_SWIPE_MEM": "Frees the previous destination buffer, moves the source pointer into that destination, and nulls the source variable. This is a replacement pattern, not a direct UAF of the new active pointer.",
    "strdup": "Returns a freshly allocated copy of the input string. Freeing the original pointer after strdup is normally not UAF.",
    "strndup": "Returns a freshly allocated copy of the input string prefix. The returned object is independent from the source buffer.",
    "memdup": "Duplicates the source buffer into new heap storage. Original and duplicate have separate ownership.",
    "snmp_clone_mem": "Allocates a fresh destination buffer and copies the source bytes into it. Source and destination do not share ownership.",
    "snmp_duplicate_objid": "Duplicates the input OID buffer into new storage. Freeing the original object afterward is normally safe.",
    "netsnmp_strdup_and_null": "Allocates a new null-terminated copy of the input bytes. The returned buffer has independent ownership from the source.",
    "netsnmp_view_create": "Copies viewName and viewSubtree into the internal VACM entry. Temporary caller-owned parse buffers may be freed after the call.",
    "netsnmp_create_data_list": "Wraps a caller-provided data pointer and free callback in a list node. Holder cleanup and payload cleanup are distinct concepts.",
    "netsnmp_table_data_delete_row": "Frees the row container but returns row->data to the caller. Later use of the returned payload is not use-after-free of the row object.",
    "snmp_set_var_value": "May replace varbind storage and free the previous heap buffer after the varbind pointer no longer references it.",
}


GENERIC_UAF_LIFECYCLE_SUMMARIES = [
    "If code frees an old buffer only after the active pointer has been replaced with a new buffer, that is a replacement pattern, not UAF.",
    "If a cleanup branch frees resources and immediately returns, later uses on a different branch do not form a valid UAF path.",
    "If a function deep-copies an input object into internal storage, freeing the temporary input buffer afterward is usually safe.",
    "Freeing a holder/container object is different from freeing its detached payload. Returning the payload after freeing only the container is not UAF by itself.",
    "If a deallocation macro also nulls the original variable, a later dereference of that same variable requires an intervening re-assignment.",
]


def _mentions_api(function_code: str, api_name: str) -> bool:
    pattern = r"\b" + re.escape(api_name) + r"\s*\("
    return re.search(pattern, function_code) is not None


def _pattern_summaries(function: Function) -> List[str]:
    code = function.function_code
    summaries: List[str] = []

    if re.search(r"free\s*\([^;]+\)\s*;\s*return\b", code):
        summaries.append(
            f"In {function.function_name}, there is a free-then-return cleanup pattern. A later use must occur on the same feasible branch after that free to be UAF."
        )

    if re.search(r"SNMP_FREE\s*\([^;]+\)\s*;\s*return\b", code):
        summaries.append(
            f"In {function.function_name}, there is an SNMP_FREE-then-return cleanup pattern. This often indicates normal error cleanup instead of UAF."
        )

    if re.search(r"return\s+data\s*;", code) and re.search(r"free\s*\(\s*row\s*\)", code):
        summaries.append(
            f"In {function.function_name}, the code frees a row/container and returns a detached payload variable. Container/payload separation should be considered before claiming UAF."
        )

    return summaries


def build_uaf_semantic_summary(functions: Iterable[Function]) -> str:
    unique_functions = []
    seen_ids = set()
    for function in functions:
        if function.function_id in seen_ids:
            continue
        seen_ids.add(function.function_id)
        unique_functions.append(function)

    lines: List[str] = []
    if not unique_functions:
        return ""

    lines.append("UAF ownership/lifecycle summaries:")
    for summary in GENERIC_UAF_LIFECYCLE_SUMMARIES:
        lines.append("- " + summary)

    emitted = set()
    for function in unique_functions:
        for api_name, summary in COMMON_UAF_API_SUMMARIES.items():
            if not _mentions_api(function.function_code, api_name):
                continue
            key = (function.function_id, api_name)
            if key in emitted:
                continue
            emitted.add(key)
            lines.append(f"- In {function.function_name}, `{api_name}`: {summary}")

        for summary in _pattern_summaries(function):
            key = (function.function_id, summary)
            if key in emitted:
                continue
            emitted.add(key)
            lines.append("- " + summary)

    return "\n".join(lines)
