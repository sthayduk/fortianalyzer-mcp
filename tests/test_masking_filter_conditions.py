"""Masked values inside structured filter conditions must resolve.

A masked IP is format-preserving and unmarked, so only the sibling `field` key
identifies it as an IP. Without that, a masked filter reaches the appliance as
a valid-but-different address and returns real logs for the wrong host.
"""

from __future__ import annotations

from fortianalyzer_mcp.masking.fpe_engine import FPEEngine
from fortianalyzer_mcp.masking.unmask import ArgUnmasker
from fortianalyzer_mcp.query.filters import FilterCondition

KEY = "0" * 64


def _engine() -> FPEEngine:
    return FPEEngine(KEY)


class TestFilterConditionDicts:
    """The dict form, as it arrives before model validation."""

    def test_masked_ip_resolves_using_the_sibling_field(self) -> None:
        engine = _engine()
        unmasker = ArgUnmasker(engine)
        token = engine.mask_ip("10.0.0.5")
        assert token != "10.0.0.5", "precondition: the IP must actually be masked"

        result = unmasker.unmask_args({"filters": [{"field": "srcip", "op": "eq", "value": token}]})

        assert result["filters"][0]["value"] == "10.0.0.5"

    def test_masked_username_resolves(self) -> None:
        engine = _engine()
        unmasker = ArgUnmasker(engine)
        token = engine.mask_username("jdoe")

        result = unmasker.unmask_args({"filters": [{"field": "user", "op": "eq", "value": token}]})

        assert result["filters"][0]["value"] == "jdoe"

    def test_masked_mac_resolves(self) -> None:
        engine = _engine()
        unmasker = ArgUnmasker(engine)
        token = engine.mask_mac("00:11:22:33:44:55")

        result = unmasker.unmask_args(
            {"filters": [{"field": "srcmac", "op": "eq", "value": token}]}
        )

        assert result["filters"][0]["value"] == "00:11:22:33:44:55"

    def test_list_values_resolve_elementwise(self) -> None:
        engine = _engine()
        unmasker = ArgUnmasker(engine)
        tokens = [engine.mask_ip("10.0.0.5"), engine.mask_ip("10.0.0.6")]

        result = unmasker.unmask_args(
            {"filters": [{"field": "srcip", "op": "in", "value": tokens}]}
        )

        assert result["filters"][0]["value"] == ["10.0.0.5", "10.0.0.6"]

    def test_unmasked_value_is_left_alone(self) -> None:
        unmasker = ArgUnmasker(_engine())
        result = unmasker.unmask_args({"filters": [{"field": "dstport", "op": "eq", "value": 443}]})
        assert result["filters"][0]["value"] == 443


class TestFilterConditionModels:
    """The model form, which is what FastMCP passes to the tool."""

    def test_model_instance_is_resolved_and_stays_a_model(self) -> None:
        engine = _engine()
        unmasker = ArgUnmasker(engine)
        token = engine.mask_ip("10.0.0.5")

        result = unmasker.unmask_args(
            {"filters": [FilterCondition(field="srcip", op="eq", value=token)]}
        )

        condition = result["filters"][0]
        assert isinstance(condition, FilterCondition)
        assert condition.value == "10.0.0.5"
        assert condition.field == "srcip"
        assert condition.op == "eq"


class TestMeasuredStringFilterBehaviour:
    """Freeze what unmask_filter does today, including what it cannot do.

    The embedded-token case is asserted as broken on purpose: it predates this
    work, a compiler cannot turn a phrase into a token, and fixing it needs
    substring resolution inside resolve_scalar. Asserting it keeps the
    limitation visible and forces a future fix to update this test knowingly.
    """

    def test_quoted_token_resolves(self) -> None:
        engine = _engine()
        unmasker = ArgUnmasker(engine)
        token = engine.mask_username("jdoe")
        assert unmasker.unmask_filter(f'user=="{token}"') == 'user=="jdoe"'

    def test_bare_token_resolves(self) -> None:
        engine = _engine()
        unmasker = ArgUnmasker(engine)
        token = engine.mask_username("jdoe")
        assert unmasker.unmask_filter(f"user=={token}") == "user==jdoe"

    def test_token_embedded_in_a_quoted_phrase_does_not_resolve(self) -> None:
        engine = _engine()
        unmasker = ArgUnmasker(engine)
        token = engine.mask_username("jdoe")
        expression = f'msg contain "login failed for {token}"'
        assert unmasker.unmask_filter(expression) == expression
