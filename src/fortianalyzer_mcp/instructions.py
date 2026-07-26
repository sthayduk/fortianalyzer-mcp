"""The server-level usage guide handed to every MCP client.

Why this exists as a separate artifact from the tool docstrings: a docstring
can only state a fact about *its own* tool. It has no way to warn that a
neighbouring tool spells something the same way and means something else.
Several tools here do exactly that, and the collisions are invisible from
inside any one of them.

The load-bearing case is ``tid``. Five families hand back a value under that
key and none of them are interchangeable -- one is a local pagination handle
that survives reuse, three are appliance task ids that do not, one is a UUID
string rather than an int, and one is inert. A caller that generalises from
the first to any other gets failures whose cause is nowhere in the docstring
it read. Arbitrating that is a server-level job.

Kept deliberately dense. This text ships on every client handshake, so it
buys its context budget back only by being the thing that prevents a wasted
tool call, never by being complete. Anything a single docstring can already
say correctly stays in that docstring.

``tests/test_server_instructions.py`` freezes the facts here that callers
misuse, so dropping a tid family or the filter grammar fails the suite even
though no code path breaks.
"""

SERVER_INSTRUCTIONS = """\
FortiAnalyzer JSON-RPC API exposed as MCP tools. Read-heavy SOC/log-analysis
surface: most tools read, and the write paths are device add/delete, incident
create/update, alert acknowledgement and file downloads.

## "tid" means five different things -- check this before reusing one

A tid from one family is never valid in another. Pairings:

| Started by        | Consumed by                          | What the tid is |
|-------------------|--------------------------------------|-----------------|
| query_logs        | fetch_more_logs, cancel_log_search   | int, REUSABLE pagination handle -- NOT the appliance task id |
| run_fortiview     | fetch_fortiview                      | int appliance task id, one-shot, only valid with the SAME view_name |
| run_report        | fetch_report, get_report_data        | a UUID string, not an int |
| run_ioc_rescan    | get_ioc_rescan_status                | int appliance task id, different job type |
| search_ips_logs   | nothing                              | vestigial echo of an already-reaped id -- not usable for anything |

The logsearch tid is the one that misleads. The appliance reaps its task
after the first fetch, so the int you get back is a local, reusable handle
into an in-process registry; fetch_more_logs re-runs the search at the new
offset rather than reading a cursor. Consequences you will observe and should
not treat as bugs: `total` is frozen at the page-0 baseline for the handle's
life while `page_total` carries the live per-page count, drift between them
is reported via `total_count_stability`/`total_drift_detected` instead of
being smoothed over, a handle is bound to the ADOM that created it
(`adom_mismatch`), and a `count == 0` page terminates paging.

Prefer the wrappers that hide the two-step entirely: get_fortiview_data,
run_and_wait_report, run_and_wait_ioc_rescan. Reach for the raw
run/fetch pairs only when you need to poll or cancel yourself.

## Filters

Prefer `filters` -- a list of structured conditions -- over the raw `filter`
string. Field names are validated before the call and the operator spelling is
handled for you:

  filters=[{"field": "srcip", "op": "eq", "value": "10.0.0.1"},
           {"field": "dstport", "op": "in", "value": [80, 443]}]

  ops: eq, ne, gt, gte, lt, lte, contains, not_contains, in, not_in
  conditions are ANDed; use `in` for OR within one field

English field names are accepted where they are unambiguous (source_ip,
destination_port, application, policy_id); bare "port" and "country" are not,
because they do not say src or dst. get_log_fields(name_filter="...") lists
what a logtype actually carries -- the unfiltered catalogue runs to hundreds of
entries.

`filter` still accepts a raw FortiAnalyzer expression for syntax `filters`
cannot express, and the two are mutually exclusive -- passing both is an error
rather than a silently merged filter. The operators the server emits are `==`,
`!=`, `<`, `>`, `<=`, `>=`, `contain` and `!contain`, combined with `and`/`or`
and grouped with parentheses. FortiAnalyzer's own parser accepts more than
that, but nothing beyond this set is verified against this API here, so treat
anything else as an experiment you run through `filter`.

search_devices and list_tasks take the same `filters` parameter, with one
exception: `in` is rejected there -- their endpoints speak an array dialect
with no verified OR form, so issue one call per value (`not_in` still works;
it compiles to ANDed `!=`). Their field sets are small enough to enumerate, so
an unknown field name there is a hard error listing the valid names; for
logtypes an unrecognised name is passed through with a warning instead, since
the appliance's catalogue is larger than the server's list.

## Choosing among overlapping tools

- Per-policy volume questions -> get_policy_traffic_profile,
  get_policy_port_analysis, get_policy_protocol_summary. These pre-aggregate
  on the appliance and report their own exactness (`is_exact`,
  `analysis_mode`, `total_hits_is_known`). Never page raw rows to answer a
  "how much" question.
- Filtering on srcip/dstip/action/policy_id -> search_traffic_logs, which
  takes typed parameters and builds the filter for you.
- Anything else, or a filter the wrappers cannot express -> query_logs.
- Top-N by dimension (destinations, apps, countries) -> the FortiView tools.

## time_range vocabularies

Two forms work everywhere: a preset token ("5-min", "1-hour", "6-hour",
"12-hour", "24-hour", "7-day", "30-day") or a custom "start|end" pair
("2026-01-01 00:00:00|2026-01-02 00:00:00"). The report tools additionally
accept the appliance's own spelling ("last-7-days", "last-30-days",
"last-4-weeks") and map the preset tokens onto it, so either works there.

Relative windows are anchored on the appliance's newest ingested log, not on
your clock, because FortiAnalyzer reads naive timestamps in its own timezone.

## Response size

list_adoms and list_devices return every field by default, most of them empty
placeholders. Both take `fields` -- pass e.g. fields=["name","state"] or
fields=["name","ip","os_ver","platform_str"] and the response shrinks by an
order of magnitude. get_log_fields takes name_filter for the same reason.

## Error shapes are not yet uniform

The log-search and traffic families return a machine-readable envelope:
`{status, error, message, operation, retry_count}`, often with a
`recommendation` naming the tool call that recovers. The remaining tool
modules currently return only `{status: "error", message: <appliance text>}`,
so branch on `status` first and treat `error` as present-if-available.
"""
