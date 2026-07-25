"""Tests for the structured filter compiler."""

from __future__ import annotations

import pytest
from pydantic import ValidationError as PydanticValidationError

from fortianalyzer_mcp.query.filters import (
    FilterCondition,
    compile_to_array,
    compile_to_string,
)
from fortianalyzer_mcp.utils.errors import ValidationError


def _c(field: str, op: str = "eq", value: object = "x") -> FilterCondition:
    """Build one condition without repeating the keyword names everywhere."""
    return FilterCondition(field=field, op=op, value=value)  # type: ignore[arg-type]


class TestStringDialectOperators:
    """Each op emits the spelling this repo has working evidence for."""

    @pytest.mark.parametrize(
        "op,expected",
        [
            ("eq", "srcip==10.0.0.1"),
            ("ne", "srcip!=10.0.0.1"),
            ("gt", "srcip>10.0.0.1"),
            ("gte", "srcip>=10.0.0.1"),
            ("lt", "srcip<10.0.0.1"),
            ("lte", "srcip<=10.0.0.1"),
        ],
    )
    def test_symbol_operators_emit_without_spaces(self, op: str, expected: str) -> None:
        result, _ = compile_to_string([_c("srcip", op, "10.0.0.1")], "traffic")
        assert result == expected

    def test_contains_emits_the_word_operator_with_spaces(self) -> None:
        result, _ = compile_to_string([_c("attack", "contains", "Botnet")], "attack")
        assert result == "attack contain Botnet"

    def test_not_contains_emits_the_negated_word_operator(self) -> None:
        result, _ = compile_to_string([_c("attack", "not_contains", "Botnet")], "attack")
        assert result == "attack !contain Botnet"


class TestStringDialectCombination:
    """AND across conditions, parenthesised OR within one field."""

    def test_multiple_conditions_are_anded(self) -> None:
        result, _ = compile_to_string(
            [_c("srcip", "eq", "10.0.0.1"), _c("dstport", "eq", 443)], "traffic"
        )
        assert result == "srcip==10.0.0.1 and dstport==443"

    def test_in_emits_a_parenthesised_or_group(self) -> None:
        result, _ = compile_to_string([_c("dstport", "in", [80, 443])], "traffic")
        assert result == "(dstport==80 or dstport==443)"

    def test_not_in_emits_a_parenthesised_and_group(self) -> None:
        result, _ = compile_to_string([_c("dstport", "not_in", [80, 443])], "traffic")
        assert result == "(dstport!=80 and dstport!=443)"

    def test_in_combines_with_a_sibling_condition(self) -> None:
        result, _ = compile_to_string(
            [_c("srcip", "eq", "10.0.0.1"), _c("dstport", "in", [80, 443])], "traffic"
        )
        assert result == "srcip==10.0.0.1 and (dstport==80 or dstport==443)"

    def test_no_conditions_compiles_to_an_empty_filter(self) -> None:
        result, warnings = compile_to_string([], "traffic")
        assert result == ""
        assert warnings == []


class TestValueHandling:
    """Quoting is the string dialect's injection boundary."""

    def test_plain_values_are_left_unquoted(self) -> None:
        result, _ = compile_to_string([_c("srcip", "eq", "10.0.0.1")], "traffic")
        assert result == "srcip==10.0.0.1"

    def test_ipv6_literals_are_not_quoted(self) -> None:
        """The traffic_tools sanitiser copy quoted these; the survivor does not."""
        result, _ = compile_to_string([_c("srcip", "eq", "2001:db8::1")], "traffic")
        assert result == "srcip==2001:db8::1"

    def test_values_with_spaces_are_quoted(self) -> None:
        result, _ = compile_to_string([_c("attack", "contains", "Remote Code")], "attack")
        assert result == 'attack contain "Remote Code"'

    def test_injection_attempt_is_neutralised_by_quoting(self) -> None:
        result, _ = compile_to_string([_c("srcip", "eq", '1.1.1.1" or 1==1 or "')], "traffic")
        assert result.startswith('srcip=="')
        assert result.count('\\"') >= 1

    def test_integer_values_survive_as_numbers(self) -> None:
        result, _ = compile_to_string([_c("dstport", "eq", 443)], "traffic")
        assert result == "dstport==443"


class TestInputRejection:
    """Bad input fails locally with a message that says what to do."""

    def test_scalar_op_with_a_list_value_raises(self) -> None:
        with pytest.raises(ValidationError) as exc:
            compile_to_string([_c("dstport", "eq", [80, 443])], "traffic")
        assert "'in'" in str(exc.value)

    def test_in_with_a_scalar_value_raises(self) -> None:
        with pytest.raises(ValidationError) as exc:
            compile_to_string([_c("dstport", "in", 80)], "traffic")
        assert "list" in str(exc.value)

    def test_in_with_an_empty_list_raises(self) -> None:
        with pytest.raises(ValidationError):
            compile_to_string([_c("dstport", "in", [])], "traffic")

    def test_boolean_value_raises(self) -> None:
        with pytest.raises(ValidationError) as exc:
            compile_to_string([_c("srcip", "eq", True)], "traffic")
        assert "boolean" in str(exc.value).lower()

    def test_unknown_op_is_rejected_by_the_model(self) -> None:
        with pytest.raises(PydanticValidationError):
            FilterCondition(field="srcip", op="matches", value="x")  # type: ignore[arg-type]

    def test_extra_keys_are_rejected_by_the_model(self) -> None:
        with pytest.raises(PydanticValidationError):
            FilterCondition(field="srcip", op="eq", value="x", extra="nope")  # type: ignore[call-arg]


class TestFieldResolution:
    """The compiler resolves names through the registry."""

    def test_alias_is_compiled_to_the_canonical_name(self) -> None:
        result, _ = compile_to_string([_c("source_ip", "eq", "10.0.0.1")], "traffic")
        assert result == "srcip==10.0.0.1"

    def test_unknown_log_field_passes_through_with_a_warning(self) -> None:
        result, warnings = compile_to_string([_c("weird_field", "eq", "x")], "traffic")
        assert result == "weird_field==x"
        assert len(warnings) == 1
        assert "get_log_fields" in warnings[0]


class TestArrayDialect:
    """dvmdb/config/task take a list of [field, op, value] entries, ANDed."""

    def test_eq_emits_one_entry(self) -> None:
        result, _ = compile_to_array([_c("name", "eq", "fgt-01")], "device")
        assert result == [["name", "==", "fgt-01"]]

    def test_contains_uses_the_appliance_word_operator(self) -> None:
        result, _ = compile_to_array([_c("name", "contains", "fgt")], "device")
        assert result == [["name", "contain", "fgt"]]

    def test_multiple_conditions_become_multiple_entries(self) -> None:
        result, _ = compile_to_array(
            [_c("name", "contains", "fgt"), _c("os_ver", "contains", "7.")], "device"
        )
        assert result == [["name", "contain", "fgt"], ["os_ver", "contain", "7."]]

    def test_enum_name_is_coerced_to_its_code(self) -> None:
        result, _ = compile_to_array([_c("conn_status", "eq", "down")], "device")
        assert result == [["conn_status", "==", 2]]

    def test_task_state_name_is_coerced_to_its_code(self) -> None:
        result, _ = compile_to_array([_c("state", "eq", "running")], "task")
        assert result == [["state", "==", 1]]

    def test_alias_resolves_before_emitting(self) -> None:
        result, _ = compile_to_array([_c("serial_number", "eq", "FG100F0000")], "device")
        assert result == [["sn", "==", "FG100F0000"]]

    def test_values_are_not_quoted_because_they_travel_as_json(self) -> None:
        result, _ = compile_to_array([_c("desc", "eq", 'has "quotes" and spaces')], "device")
        assert result == [["desc", "==", 'has "quotes" and spaces']]

    def test_not_in_becomes_one_negated_entry_per_value(self) -> None:
        result, _ = compile_to_array([_c("name", "not_in", ["a", "b"])], "device")
        assert result == [["name", "!=", "a"], ["name", "!=", "b"]]

    def test_in_is_refused_rather_than_guessed(self) -> None:
        with pytest.raises(ValidationError) as exc:
            compile_to_array([_c("name", "in", ["a", "b"])], "device")
        assert "one call per value" in str(exc.value)

    def test_no_conditions_compiles_to_an_empty_list(self) -> None:
        result, warnings = compile_to_array([], "device")
        assert result == []
        assert warnings == []

    def test_unknown_device_field_raises_because_the_set_is_complete(self) -> None:
        with pytest.raises(ValidationError):
            compile_to_array([_c("not_a_device_field", "eq", "x")], "device")
