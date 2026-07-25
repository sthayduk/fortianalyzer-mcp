"""Structured filter conditions, compiled to FortiAnalyzer's filter dialects.

FortiAnalyzer speaks two unrelated filter syntaxes and this module owns both:

* the **string dialect** -- logview, fortiview, eventmgmt, incidentmgmt:
  ``"srcip==10.0.0.1 and dstport==443"``, with parenthesised OR groups.
* the **array dialect** -- dvmdb, config, task:
  ``[["name", "contain", "fgt"], ["conn_status", "==", 2]]``, entries
  implicitly ANDed.

Callers describe a query once as ``FilterCondition`` objects; this module emits
whichever dialect the endpoint speaks. That is what makes operator spelling
consistent: before this existed the repo spelled "contains" two ways
(``attack contain X`` in log_tools, ``attack=*X*`` in pcap_tools) and carried
two sanitisers with different safe-character classes.

Only operator spellings with working evidence against a live appliance are
emitted. FortiAnalyzer 7.0.1 also documents ``like``, ``~``, ``!~``, ``isnull``,
``isnotnull`` and ``<>`` for its Log View parser, but none is exercised through
JSON-RPC anywhere in this repo, so they are deliberately absent until a live
check confirms them -- see the spec's verification items. The op set is data, so
adding one later is a one-line change.

Quoting is a *string-dialect* concern only. Array-dialect values travel as JSON
scalars and are never interpolated into a string, so they need no escaping.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Literal

from pydantic import BaseModel, ConfigDict

from fortianalyzer_mcp.query.fields import coerce_value, resolve_field
from fortianalyzer_mcp.utils.validation import ValidationError, sanitize_filter_value

FilterOp = Literal[
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
]

#: Ops that emit as a symbol with no surrounding spaces (``srcip==1.2.3.4``).
_SYMBOL_OPS: dict[str, str] = {
    "eq": "==",
    "ne": "!=",
    "gt": ">",
    "gte": ">=",
    "lt": "<",
    "lte": "<=",
}

#: Ops that emit as a bare word and need spaces (``attack contain Botnet``).
_WORD_OPS: dict[str, str] = {
    "contains": "contain",
    "not_contains": "!contain",
}

_MULTI_VALUE_OPS = frozenset({"in", "not_in"})


class FilterCondition(BaseModel):
    """One field/operator/value condition, independent of dialect.

    A Pydantic model rather than a dict so FastMCP publishes a real JSON schema
    for it -- including the ``op`` enum, which is what stops an invalid operator
    at the protocol boundary instead of at the appliance.
    """

    model_config = ConfigDict(extra="forbid")

    field: str
    op: FilterOp = "eq"
    value: str | bool | int | float | list[str | int]


def _reject_bool(field: str, value: object) -> None:
    """Reject booleans. ``bool`` is a subclass of ``int``, so check it first."""
    if isinstance(value, bool):
        raise ValidationError(
            f"Filter on '{field}' has a boolean value. FortiAnalyzer filters compare "
            "against text or numbers -- pass the concrete value instead."
        )


def _scalar(condition: FilterCondition) -> str | int | float:
    """Return the single value for a scalar op."""
    value = condition.value
    if isinstance(value, list):
        raise ValidationError(
            f"Filter on '{condition.field}' with op '{condition.op}' takes one value, not "
            "a list. Use op 'in' or 'not_in' for multiple values."
        )
    _reject_bool(condition.field, value)
    return value


def _values(condition: FilterCondition) -> list[str | int]:
    """Return the value list for ``in``/``not_in``."""
    value = condition.value
    if not isinstance(value, list):
        raise ValidationError(
            f"Filter on '{condition.field}' with op '{condition.op}' takes a list of "
            "values, not a single value."
        )
    if not value:
        raise ValidationError(
            f"Filter on '{condition.field}' has an empty value list; nothing to match."
        )
    for item in value:
        _reject_bool(condition.field, item)
    return list(value)


def _quote(value: str | int | float, field: str) -> str:
    """Sanitise one value for interpolation into the string dialect."""
    return sanitize_filter_value(str(value), field)


def compile_to_string(
    conditions: Sequence[FilterCondition],
    vocabulary: str,
) -> tuple[str, list[str]]:
    """Compile conditions into the string dialect, ANDed together.

    ``in``/``not_in`` become parenthesised groups. Parentheses are supported:
    the administration guide documents
    ``dstip==192.168.1.168 and ( dstport == 514 or dstport == 515 )``, and this
    repo already ships ``(severity="critical" or severity="high")``.

    Args:
        conditions: The conditions to compile. Empty yields an empty filter.
        vocabulary: The logtype or object type whose field names apply.

    Returns:
        ``(filter_string, warnings)``. ``warnings`` holds one entry per field
        name that was passed through unrecognised.

    Raises:
        ValidationError: on a value/op mismatch, a boolean value, or an unknown
            field in a vocabulary that enumerates its fields.
    """
    clauses: list[str] = []
    warnings: list[str] = []

    for condition in conditions:
        field, warning = resolve_field(vocabulary, condition.field)
        if warning:
            warnings.append(warning)

        op = condition.op
        if op in _MULTI_VALUE_OPS:
            values = [coerce_value(vocabulary, field, v) for v in _values(condition)]
            if op == "in":
                inner = " or ".join(f"{field}=={_quote(v, field)}" for v in values)
            else:
                inner = " and ".join(f"{field}!={_quote(v, field)}" for v in values)
            clauses.append(f"({inner})")
            continue

        value = coerce_value(vocabulary, field, _scalar(condition))
        if op in _SYMBOL_OPS:
            clauses.append(f"{field}{_SYMBOL_OPS[op]}{_quote(value, field)}")
        else:
            clauses.append(f"{field} {_WORD_OPS[op]} {_quote(value, field)}")

    return " and ".join(clauses), warnings


#: Array-dialect operator spellings. ``search_devices`` proves ``==`` and
#: ``contain`` against a live appliance; the comparison operators follow the
#: same FortiManager grammar.
_ARRAY_OPS: dict[str, str] = {
    "eq": "==",
    "ne": "!=",
    "gt": ">",
    "gte": ">=",
    "lt": "<",
    "lte": "<=",
    "contains": "contain",
    "not_contains": "!contain",
}


def compile_to_array(
    conditions: Sequence[FilterCondition],
    vocabulary: str,
) -> tuple[list[list[object]], list[str]]:
    """Compile conditions into the array dialect (dvmdb, config, task).

    Entries are implicitly ANDed, the only combining form proven here --
    ``search_devices`` and ``list_tasks`` both rely on it. Values are *not*
    quoted or escaped: they travel as JSON scalars and are never interpolated
    into a filter string, so the string dialect's injection boundary does not
    apply.

    ``in`` is refused rather than guessed. Its explicit OR-separator syntax is
    documented for FortiManager but unexercised in this repo, and the tempting
    fallback -- one ``contain`` over a shared prefix -- is wrong, because it
    silently matches values the caller never asked for.

    Returns:
        ``(entries, warnings)``.

    Raises:
        ValidationError: on ``in``, a value/op mismatch, a boolean value, or an
            unknown field.
    """
    entries: list[list[object]] = []
    warnings: list[str] = []

    for condition in conditions:
        field, warning = resolve_field(vocabulary, condition.field)
        if warning:
            warnings.append(warning)

        op = condition.op
        if op in _ARRAY_OPS:
            value = coerce_value(vocabulary, field, _scalar(condition))
            entries.append([field, _ARRAY_OPS[op], value])
            continue

        if op == "not_in":
            for item in _values(condition):
                entries.append([field, "!=", coerce_value(vocabulary, field, item)])
            continue

        raise ValidationError(
            f"Filter op '{op}' on '{field}' is not supported against this endpoint. "
            "Issue one call per value instead."
        )

    return entries, warnings
