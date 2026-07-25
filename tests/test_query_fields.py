"""Tests for the query vocabulary registry."""

from __future__ import annotations

import pytest

from fortianalyzer_mcp.query.fields import (
    coerce_value,
    get_vocabulary,
    resolve_field,
)
from fortianalyzer_mcp.utils.errors import ValidationError


class TestResolveField:
    """Canonical names, aliases, and the strict/non-strict split."""

    def test_canonical_name_resolves_to_itself(self) -> None:
        assert resolve_field("traffic", "srcip") == ("srcip", None)

    def test_alias_resolves_to_canonical(self) -> None:
        assert resolve_field("traffic", "source_ip") == ("srcip", None)

    def test_alias_resolution_is_case_insensitive(self) -> None:
        assert resolve_field("traffic", "Source_IP") == ("srcip", None)

    def test_canonical_wins_over_alias(self) -> None:
        """An alias may never shadow a real field name."""
        vocab = get_vocabulary("device")
        for alias in vocab.aliases:
            assert alias not in vocab.canonical, f"alias {alias!r} shadows a canonical field"

    def test_unknown_field_on_incomplete_vocabulary_warns_and_passes_through(self) -> None:
        canonical, warning = resolve_field("traffic", "some_unlisted_field")
        assert canonical == "some_unlisted_field"
        assert warning is not None
        assert "get_log_fields" in warning

    def test_unknown_field_on_complete_vocabulary_raises(self) -> None:
        with pytest.raises(ValidationError) as exc:
            resolve_field("device", "definitely_not_a_field")
        assert "conn_status" in str(exc.value)

    def test_unregistered_logtype_falls_back_to_the_generic_log_vocabulary(self) -> None:
        canonical, warning = resolve_field("voip", "srcip")
        assert canonical == "srcip"
        assert warning is None


class TestCoerceValue:
    """LLM-friendly enum names become the codes FortiAnalyzer stores."""

    def test_device_connection_status_name_becomes_code(self) -> None:
        assert coerce_value("device", "conn_status", "down") == 2

    def test_coercion_is_case_insensitive(self) -> None:
        assert coerce_value("device", "conn_status", "UP") == 1

    def test_task_state_name_becomes_code(self) -> None:
        assert coerce_value("task", "state", "running") == 1

    def test_already_numeric_value_passes_through(self) -> None:
        assert coerce_value("device", "conn_status", 2) == 2

    def test_unknown_enum_name_raises_listing_valid_values(self) -> None:
        with pytest.raises(ValidationError) as exc:
            coerce_value("device", "conn_status", "sideways")
        message = str(exc.value)
        assert "up" in message and "down" in message

    def test_field_without_coercions_passes_value_through(self) -> None:
        assert coerce_value("traffic", "srcip", "10.0.0.1") == "10.0.0.1"


class TestRegistryMatchesTheToolsItReplaces:
    """The registry duplicates two enum maps; assert they cannot drift apart."""

    def test_task_state_codes_match_system_tools(self) -> None:
        from fortianalyzer_mcp.query.fields import _TASK_STATE_CODES
        from fortianalyzer_mcp.tools.system_tools import _TASK_STATE_CODES as TOOL_CODES

        assert dict(_TASK_STATE_CODES) == dict(TOOL_CODES)

    def test_conn_status_codes_cover_the_documented_names(self) -> None:
        from fortianalyzer_mcp.query.fields import _CONN_STATUS_CODES

        assert dict(_CONN_STATUS_CODES) == {"unknown": 0, "up": 1, "down": 2}
