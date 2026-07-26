"""Contract tests for the server-level ``instructions`` block.

``FastMCP(instructions=...)`` is the only text this server ships that a
client reads *before* choosing a tool. Per-tool docstrings cannot carry a
cross-cutting fact, because a caller holding one tool's docstring has no
reason to suspect a neighbouring tool disagrees -- and here several do.

The fact these tests exist to protect is the **tid taxonomy**. Five tool
families return something spelled ``tid``, and the values are not
interchangeable:

* ``query_logs`` -> an int that is a *reusable pagination handle*, not the
  appliance task id (the appliance reaps that after one fetch).
* ``run_fortiview`` -> an int appliance task id, one-shot, and only valid
  when re-paired with the same ``view_name``.
* ``run_report`` -> a UUID *string*, not an int.
* ``run_ioc_rescan`` -> an int appliance task id of a different job type.
* ``search_ips_logs`` -> a vestigial echo of a reaped id; not usable at all.

A caller that generalises "I hold a tid, so I can page it" from the first
to any of the others gets confusing failures. That is the misuse this
block prevents, so a change that drops a family from it is a regression
even though no code path breaks.

Assertions target tool names and operator tokens rather than prose, so the
wording stays free to change while the load-bearing facts cannot silently
go missing.
"""

import importlib

import pytest

#: Each async family that hands back a value spelled ``tid``, mapped to the
#: tools that consume it. Every name here must appear in the instructions:
#: a family absent from the taxonomy is a family a caller will guess about.
TID_FAMILIES = {
    "query_logs": ("fetch_more_logs", "cancel_log_search"),
    "run_fortiview": ("fetch_fortiview",),
    "run_report": ("fetch_report", "get_report_data"),
    "run_ioc_rescan": ("get_ioc_rescan_status",),
    "search_ips_logs": (),
}

#: The FortiAnalyzer filter grammar the server itself emits. The raw
#: ``filter`` string remains an escape hatch, so the operator set belongs
#: where it is read up front.
FILTER_OPERATORS = ("==", "!=", "<=", ">=", "contain", "!contain")

#: The ``filters`` op vocabulary. This is the surface a caller must get
#: right, and it is validated locally, so it is the more load-bearing list.
STRUCTURED_FILTER_OPS = (
    "eq",
    "ne",
    "gt",
    "gte",
    "lt",
    "lte",
    "contains",
    "not_contains",
    "in",
    "not_in",
)


@pytest.fixture(scope="module")
def instructions() -> str:
    """The live ``instructions`` string off the module-global FastMCP."""
    server = importlib.import_module("fortianalyzer_mcp.server")
    text = server.mcp.instructions
    assert text is not None, "FastMCP was constructed without instructions="
    return text


def test_server_declares_instructions(instructions: str) -> None:
    """The server ships a usage guide at all.

    Without this, a client sees 84 tool docstrings and no arbitration
    between them.
    """
    assert instructions.strip(), "instructions= is present but empty"


@pytest.mark.parametrize("starter", sorted(TID_FAMILIES))
def test_instructions_name_every_tid_starter(instructions: str, starter: str) -> None:
    """Every tool that *hands out* a tid is named in the taxonomy."""
    assert starter in instructions, f"{starter} returns a tid but is undocumented"


@pytest.mark.parametrize(
    "consumer",
    sorted(name for consumers in TID_FAMILIES.values() for name in consumers),
)
def test_instructions_name_every_tid_consumer(instructions: str, consumer: str) -> None:
    """Every tool that *takes* a tid is named, paired with its starter."""
    assert consumer in instructions, f"{consumer} consumes a tid but is undocumented"


def test_instructions_mark_the_logsearch_tid_as_a_reusable_handle(instructions: str) -> None:
    """The query_logs tid must be distinguished from an appliance task id.

    This is the single most misusable fact in the server: the value is a
    local pagination handle, so it survives repeated use, while every
    other tid does not.
    """
    assert "reusable" in instructions.lower()


def test_instructions_mark_the_ips_tid_as_unusable(instructions: str) -> None:
    """search_ips_logs' tid is shape-identical to a handle but is inert."""
    lowered = instructions.lower()
    assert "vestigial" in lowered or "not usable" in lowered


def test_instructions_state_the_report_tid_is_a_string(instructions: str) -> None:
    """run_report breaks the int assumption every other family sets."""
    assert "uuid" in instructions.lower()


@pytest.mark.parametrize("operator", FILTER_OPERATORS)
def test_instructions_document_the_filter_operator_set(instructions: str, operator: str) -> None:
    """The filter grammar is stated up front, not only on failure."""
    assert operator in instructions, f"filter operator {operator!r} undocumented"


def test_instructions_point_large_result_sets_at_the_aggregation_tools(
    instructions: str,
) -> None:
    """A caller facing 100k rows should be steered off raw paging.

    The policy family pre-aggregates server-side and is honest about
    exactness; paging 100k rows through an LLM context is never the right
    answer to a volume question.
    """
    assert "get_policy_traffic_profile" in instructions


def test_instructions_document_the_field_trim_escape_hatch(instructions: str) -> None:
    """list_adoms/list_devices default to every field; say so.

    The ``fields`` parameter has always existed on both. A reviewer with
    live access still concluded ``list_devices`` had none, which is
    precisely the cost of leaving it undocumented here.
    """
    assert "fields" in instructions
    assert "list_adoms" in instructions
    assert "list_devices" in instructions


@pytest.mark.parametrize("op", STRUCTURED_FILTER_OPS)
def test_structured_filter_ops_are_documented(instructions: str, op: str) -> None:
    """The op vocabulary is what a caller must get right; freeze it."""
    assert op in instructions, f"op {op!r} missing from the usage guide"


def test_filters_parameter_is_named(instructions: str) -> None:
    assert "filters" in instructions


def test_in_is_caveated_for_the_array_dialect_tools(instructions: str) -> None:
    """``in`` hard-errors on search_devices/list_tasks (compile_to_array
    refuses it), so a guide listing ``in`` unqualified beside "the same
    filters parameter" promises an op that fails on two of its consumers.
    The remedy phrase is asserted because it matches the error the caller
    would otherwise hit blind.
    """
    assert "search_devices" in instructions
    assert "list_tasks" in instructions
    assert "one call per value" in instructions


def test_unverified_operators_are_not_advertised(instructions: str) -> None:
    """like/regex/isnull are documented by Fortinet but unproven through the
    API here, so the guide must not promise them.

    Naming them even as "unverified" puts them in front of a model that will
    then try them, so the guide states the boundary without the vocabulary.
    """
    for token in (" like ", "isnull", "isnotnull"):
        assert token not in instructions
