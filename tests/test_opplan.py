import ast
import builtins
import copy
import json
import math
import re
import time
from pathlib import Path

import pytest
from hypothesis import assume, event, given, settings
from hypothesis import strategies as st

import boxed.opplan
from boxed.opplan import (
    Column,
    data_like_header,
    guess_decimal,
    normalize_rows,
    Plan,
    PlanError,
    TableSchema,
    infer_schema,
    parse_plan,
    plan_columns,
    plan_prompt,
    run_plan,
    synthetic_rows,
)


def types(header, rows):
    return [c.type for c in infer_schema(header, rows).columns]


def test_infer_schema_types():
    header = ["id", "price", "day", "paid", "note", "empty"]
    rows = [
        ["1", "9.50", "2026-10-21", "true", "first", ""],
        ["-20", "3", "2024-02-29", "FALSE", "", " "],
        ["", "", "", "", "second", ""],
        ["7", " 1000.5 ", " 2026-01-02 ", "True", "x", ""],
    ]
    schema = infer_schema(header, rows)
    assert [(c.name, c.type) for c in schema.columns] == [
        ("id", "int"),
        ("price", "float"),
        ("day", "date"),
        ("paid", "bool"),
        ("note", "text"),
        ("empty", "text"),
    ]
    assert schema.rows == 4


@pytest.mark.parametrize(
    "cells",
    [
        ["12", "abc"],
        ["007", "12"],  # a leading zero marks an identifier
        ["+79991234567"],
        ["1,5", "2,25"],  # the decimal comma is not read
        ["1_000"],
        ["١٢٣"],  # non-ASCII digits
        ["nan"],
        ["inf"],
        ["1e999"],
        ["1E5"],  # an exponent form is a code, not a quantity
        ["1e5"],
        ["2.5e-3", "1.5"],
        ["1E+5", "7"],
        ["1" * 5000],  # more digits than Python converts
        ["1234567890123456"],  # 16 digits: an identifier (a card, an account), not a quantity
        ["-1234567890123456"],
        ["12345678901234567890", "1.5"],  # next to decimals it would round to a float
        ["1234567890123456", "7"],
        ["2026-13-01"],
        ["2026-02-29"],
        ["2026-1-5"],
        ["2026-W43-3"],  # Python reads it, but a date cell is exactly YYYY-MM-DD
        ["2026-10-21T10:00:00"],
        ["yes", "no"],
    ],
)
def test_infer_schema_keeps_identifiers_and_odd_numbers_as_text(cells):
    assert types(["c"], [[c] for c in cells]) == ["text"]


def test_infer_schema_reads_whole_numbers_of_up_to_15_digits():
    # a float keeps 15 digits exactly, so these are quantities
    assert types(["c"], [["123456789012345"], ["-123456789012345"], ["7"]]) == ["int"]
    assert types(["c"], [["123456789012345"], ["1.5"]]) == ["float"]


def test_infer_schema_refuses_ragged_rows_and_repeated_names():
    with pytest.raises(PlanError, match="row 2 "):
        infer_schema(["a", "b"], [["1", "2"], ["3"]])
    with pytest.raises(PlanError, match="row 1 "):
        infer_schema(["a", "b"], [["1", "2", "3"]])
    with pytest.raises(PlanError, match="same name") as e:
        infer_schema(["ivan@acme.com", "ivan@acme.com"], [])
    assert "ivan" not in str(e.value)


def test_column_refuses_an_unknown_type():
    with pytest.raises(ValueError):
        Column("a", "string")


def test_synthetic_rows_match_the_schema_and_the_seed():
    names = ["n", "x", "d", "b", "t"]
    kinds = ["int", "float", "date", "bool", "text"]
    schema = TableSchema([Column(n, k) for n, k in zip(names, kinds)], rows=3000)
    rows = synthetic_rows(schema, n=4, seed=5)
    assert len(rows) == 4 and all(len(r) == 5 for r in rows)
    assert types(names, rows) == kinds
    # generated, not picked from a list of familiar values
    assert all(100_000 <= int(r[0]) < 1_000_000 and re.fullmatch(r"[0-9]+\.[0-9]{2}", r[1]) for r in rows)
    assert all(re.fullmatch(r"sample-[a-z0-9]{6}", r[4]) for r in rows) and len({r[4] for r in rows}) == 4
    assert rows == synthetic_rows(schema, n=4, seed=5)
    assert rows != synthetic_rows(schema, n=4, seed=6)
    assert synthetic_rows(schema) == synthetic_rows(schema, n=3, seed=0)
    assert synthetic_rows(schema, n=0) == []


def test_synthetic_rows_depend_only_on_types_and_seed():
    header = ["client", "amount"]
    a = infer_schema(header, [["Acme Corp", "10.5"], ["Globex", "99"]])
    b = infer_schema(header, [["x", "1.5"]] * 7)
    assert a != b and a.columns == b.columns
    assert synthetic_rows(a, seed=3) == synthetic_rows(b, seed=3)


CELLS = {
    "text": st.text(max_size=12),
    "number": st.one_of(st.integers().map(str), st.floats(allow_nan=False, allow_infinity=False).map(repr)),
}


@st.composite
def tables(draw):
    kinds = draw(st.lists(st.sampled_from(sorted(CELLS)), min_size=1, max_size=5))
    rows = draw(st.lists(st.tuples(*(CELLS[k] for k in kinds)).map(list), min_size=1, max_size=8))
    return [f"c{i}" for i in range(len(kinds))], rows


@settings(max_examples=300, deadline=None)
@given(tables(), st.integers(0, 2**32))
def test_synthetic_rows_share_no_real_value(table, seed):
    header, rows = table
    schema = infer_schema(header, rows)
    # a bool column has two possible values: a synthetic "true" says nothing about the data
    assume(all(c.type in ("int", "float", "text") for c in schema.columns))
    synthetic = {cell for row in synthetic_rows(schema, n=5, seed=seed) for cell in row}
    assert synthetic.isdisjoint({cell for row in rows for cell in row})


SCHEMA = TableSchema(
    [
        Column("client", "text"),
        Column("region", "text"),
        Column("revenue", "float"),
        Column("cost", "float"),
        Column("qty", "int"),
        Column("day", "date"),
        Column("paid", "bool"),
    ],
    rows=3000,
)

TOP10 = [
    {"op": "derive", "name": "margin", "left": "revenue", "operator": "-", "right": "cost"},
    {"op": "group", "by": ["client"], "aggregates": {"total": ["sum", "margin"]}},
    {"op": "sort", "by": ["total"], "desc": True},
    {"op": "limit", "n": 10},
]


def plan(*steps):
    return json.dumps({"version": 1, "steps": list(steps)})


def limit(n=5):
    return {"op": "limit", "n": n}


def flt(**kw):
    return {"op": "filter", "column": "qty", "cmp": ">", "value": 1} | kw


def derive(**kw):
    return {"op": "derive", "name": "m", "left": "revenue", "operator": "-", "right": "cost"} | kw


def group(**kw):
    return {"op": "group", "by": ["client"], "aggregates": {"total": ["sum", "revenue"]}} | kw


def sort(**kw):
    return {"op": "sort", "by": ["client"], "desc": False} | kw


def select(columns):
    return {"op": "select", "columns": columns}


def chart(**kw):
    return {"op": "chart", "kind": "bar", "x": "client", "y": "revenue"} | kw


def test_parse_plan_inside_a_fence():
    body = plan(*TOP10)
    for text in (
        body,
        f"  \n{body}\n  ",
        f"```json\n{body}\n```",
        f"```JSON\n{body}\n```",
        f"```\n{json.dumps(json.loads(body), indent=2)}\n```",
        f"Here is the plan:\n\n```json\r\n{body}\r\n```\n\nTell me if it needs changes.",
        f"```json {body}```",
    ):
        assert parse_plan(text, SCHEMA) == Plan(steps=TOP10)


def test_parse_plan_accepts_every_operation():
    steps = [
        {"op": "filter", "column": "paid", "cmp": "==", "value": True},
        {"op": "filter", "column": "paid", "cmp": "!=", "value": False},
        {"op": "filter", "column": "day", "cmp": ">=", "value": "2026-01-01"},
        {"op": "filter", "column": "client", "cmp": "contains", "value": "Corp"},
        {"op": "filter", "column": "region", "cmp": "==", "value": "EU"},
        {"op": "filter", "column": "qty", "cmp": "<", "value": 99.5},
        {"op": "filter", "column": "revenue", "cmp": "<=", "value": 7},
        {"op": "derive", "name": "margin", "left": "revenue", "operator": "-", "right": "cost"},
        {"op": "derive", "name": "per unit", "left": "margin", "operator": "/", "right": "qty"},
        {"op": "derive", "name": "taxed (20%)", "left": "revenue", "operator": "*", "right": 1.2},
        {"op": "derive", "name": "plus", "left": "qty", "operator": "+", "right": 3},
        {"op": "derive", "name": "Маржа %", "left": "plus", "operator": "-", "right": "plus"},
        {"op": "derive", "name": "m" * 64, "left": "plus", "operator": "-", "right": 1},
        {
            "op": "group",
            "by": ["client", "region"],
            "aggregates": {
                "total": ["sum", "margin"],
                "orders": ["count", "client"],
                "avg": ["mean", "taxed (20%)"],
                "first": ["min", "day"],
                "last": ["max", "day"],
            },
        },
        {"op": "sort", "by": ["total", "client"], "desc": True},
        {"op": "limit", "n": 10000},
        {"op": "select", "columns": ["client", "total"]},
        {"op": "chart", "kind": "bar", "x": "client", "y": "total"},
    ]
    assert parse_plan(plan(*steps), SCHEMA).steps == steps
    totals = [{"op": "group", "by": [], "aggregates": {"n": ["count", "client"]}}]
    assert parse_plan(plan(*totals), SCHEMA).steps == totals


def test_parse_plan_follows_the_columns_through_the_steps():
    steps = [
        derive(name="margin"),
        group(aggregates={"revenue": ["sum", "revenue"], "n": ["count", "client"], "last": ["max", "day"], "avg": ["mean", "margin"]}),
        # a name may be reused after group, and the types follow the aggregates
        {"op": "derive", "name": "per order", "left": "revenue", "operator": "/", "right": "n"},
        flt(column="last", cmp=">", value="2026-01-01"),
        select(["client", "per order"]),
        sort(by=["per order"], desc=True),
        chart(kind="line", x="client", y="per order"),
    ]
    assert parse_plan(plan(*steps), SCHEMA).steps == steps


def test_parse_plan_wants_one_complete_code_block_or_none():
    body = plan(limit())
    quoting = plan(flt(column="client", cmp="contains", value="```a``` ```b```"))  # bare JSON that mentions fences
    for text in (f"```json\n{body}\n```\nor\n```json\n{body}\n```", f"```json\n{body}", f"{body}\n```", quoting):
        with pytest.raises(PlanError, match="code block"):
            parse_plan(text, SCHEMA)


def refused(name, steps, n):
    return pytest.param(plan(*steps), f"step {n}: ", id=name)


def refused_text(name, text):
    return pytest.param(text, "plan: ", id=name)


REFUSED = [
    refused("unknown op", [limit(), {"op": "zzleak"}], 2),
    refused("op is not a string", [{"op": ["limit"]}], 1),
    refused("extra key", [limit() | {"zzleak": 1}], 1),
    refused("missing key", [{"op": "limit"}], 1),
    refused("step is not an object", [limit(), "zzleak"], 2),
    refused("unknown column", [flt(column="zzleak")], 1),
    refused("column is not a string", [flt(column=["client"])], 1),
    refused("column dropped by group", [group(), flt(column="region", cmp="==", value="EU")], 2),
    refused("column dropped by select", [select(["client"]), sort(by=["revenue"])], 2),
    refused("import as a column", [limit(), limit(), select(["__import__('os').system('id')"])], 3),
    refused("string where a number is needed", [flt(value="5zzleak")], 1),
    refused("string for n", [limit("10")], 1),
    refused("n over the cap", [limit(98765)], 1),
    refused("n is zero", [limit(0)], 1),
    refused("n is a bool", [limit(True)], 1),
    refused("n is a float", [limit(10.0)], 1),
    refused("bad comparison", [flt(cmp="zzleak")], 1),
    refused("ordering on text", [flt(column="client", cmp=">", value="a")], 1),
    refused("ordering on bool", [flt(column="paid", cmp=">", value=True)], 1),
    refused("contains on a number", [flt(cmp="contains", value=5)], 1),
    refused("number for text", [flt(column="client", cmp="==", value=5)], 1),
    refused("string for bool", [flt(column="paid", cmp="==", value="true")], 1),
    refused("number for bool", [flt(column="paid", cmp="==", value=1)], 1),
    refused("bool for a number", [flt(cmp="==", value=True)], 1),
    refused("null value", [flt(value=None)], 1),
    refused("list value", [flt(value=[1])], 1),
    refused("lone surrogate as a value", [flt(column="client", cmp="==", value="\ud800")], 1),
    refused("lone surrogate inside a value", [flt(column="client", cmp="contains", value="a\udc80b")], 1),
    refused("lone surrogate in a new name", [derive(name="m\udfff")], 1),
    refused("malformed date", [flt(column="day", cmp="==", value="2026-1-5")], 1),
    refused("impossible date", [flt(column="day", cmp="==", value="2026-02-30")], 1),
    refused("number for date", [flt(column="day", cmp="==", value=20261021)], 1),
    refused("derive on text", [derive(left="client")], 1),
    refused("derive on bool", [derive(left="paid")], 1),
    refused("derive on date", [derive(right="day")], 1),
    refused("derive unknown right column", [derive(right="zzleak")], 1),
    refused("derive bool literal", [derive(right=True)], 1),
    refused("derive null literal", [derive(right=None)], 1),
    refused("derive bad operator", [derive(operator="**")], 1),
    refused("derive name taken", [derive(name="revenue")], 1),
    refused("derive name taken by an earlier derive", [derive(), derive()], 2),
    refused("derive name starts like a formula", [derive(name="=zzleak|' /C calc'!A0")], 1),
    refused("derive name empty", [derive(name="")], 1),
    refused("derive name starts with a space", [derive(name=" m")], 1),
    refused("derive name too long", [derive(name="m" * 65)], 1),
    refused("derive name is a number", [derive(name=5)], 1),
    refused("derive name with a line break", [derive(name="m\nzzleak")], 1),
    refused("derive name with a quote", [derive(name='m"zzleak')], 1),
    refused("derive name starts with a sign", [derive(name="-zzleak")], 1),
    refused("derive name starts with an underscore", [derive(name="_zzleak")], 1),
    refused("group without aggregates", [group(aggregates={})], 1),
    refused("aggregates is a list", [group(aggregates=[["sum", "revenue"]])], 1),
    refused("unknown aggregate", [group(aggregates={"t": ["median", "revenue"]})], 1),
    refused("aggregate without a column", [group(aggregates={"t": ["sum"]})], 1),
    refused("aggregate with two columns", [group(aggregates={"t": ["sum", "revenue", "cost"]})], 1),
    refused("aggregate is a string", [group(aggregates={"t": "sum"})], 1),
    refused("sum of text", [group(aggregates={"t": ["sum", "client"]})], 1),
    refused("mean of bool", [group(aggregates={"t": ["mean", "paid"]})], 1),
    refused("min of text", [group(aggregates={"t": ["min", "client"]})], 1),
    refused("max of bool", [group(aggregates={"t": ["max", "paid"]})], 1),
    refused("aggregate named like a by column", [group(aggregates={"client": ["sum", "revenue"]})], 1),
    refused("aggregate name starts like a formula", [group(aggregates={"=zzleak": ["sum", "revenue"]})], 1),
    refused("21 aggregates", [group(aggregates={f"a{i}": ["sum", "revenue"] for i in range(21)})], 1),
    refused("group by twice the same column", [group(by=["client", "client"])], 1),
    refused("group by is a string", [group(by="client")], 1),
    refused("sort without columns", [sort(by=[])], 1),
    refused("sort twice by the same column", [sort(by=["client", "client"])], 1),
    refused("sort desc is a string", [sort(desc="true")], 1),
    refused("sort desc is a number", [sort(desc=1)], 1),
    refused("sort without desc", [{"op": "sort", "by": ["client"]}], 1),
    refused("select nothing", [select([])], 1),
    refused("select twice the same column", [select(["client", "client"])], 1),
    refused("select a string", [select("client")], 1),
    refused("chart before the last step", [chart(), limit()], 1),
    refused("two charts", [chart(), chart()], 1),
    refused("chart of text", [chart(y="client")], 1),
    refused("chart of unknown kind", [chart(kind="zzleak")], 1),
    refused("chart on unknown column", [chart(x="zzleak")], 1),
    refused_text("51 steps", plan(*[limit()] * 51)),
    refused_text("no steps", plan()),
    refused_text("not JSON", "I cannot do that, zzleak"),
    refused_text("empty answer", ""),
    refused_text("JSON in prose without a fence", f"Here you go: {plan(limit())}"),
    refused_text("text after the object", f"{plan(limit())} zzleak"),
    refused_text("array on top", "[1]"),
    refused_text("no steps key", '{"version": 1}'),
    refused_text("extra key on top", f'{{"version": 1, "steps": [{json.dumps(limit())}], "zzleak": 1}}'),
    refused_text("version 2", f'{{"version": 2, "steps": [{json.dumps(limit())}]}}'),
    refused_text("version true", f'{{"version": true, "steps": [{json.dumps(limit())}]}}'),
    refused_text("version as a string", f'{{"version": "1", "steps": [{json.dumps(limit())}]}}'),
    refused_text("version as a float", f'{{"version": 1.0, "steps": [{json.dumps(limit())}]}}'),
    refused_text("steps is a string", '{"version": 1, "steps": "zzleak"}'),
    refused_text("steps is an object", '{"version": 1, "steps": {}}'),
    refused_text("NaN", '{"version": 1, "steps": [{"op": "limit", "n": NaN}]}'),
    refused_text("Infinity", '{"version": 1, "steps": [{"op": "filter", "column": "qty", "cmp": ">", "value": Infinity}]}'),
    refused_text("number past the float range", '{"version": 1, "steps": [{"op": "filter", "column": "qty", "cmp": ">", "value": 1e999}]}'),
    refused_text("repeated key", '{"version": 1, "steps": [{"op": "limit", "n": 5, "n": 6}]}'),
    refused_text("nesting past the parser", "[" * 50_000),
    refused_text("two code blocks", f"```json\n{plan(limit())}\n```\nor\n```json\n{plan(limit())}\n```"),
    refused_text("unterminated code block", f"```json\n{plan(limit())}"),
    refused_text("answer too long", " " * 200_000 + plan(limit())),
]


@pytest.mark.parametrize(("text", "prefix"), REFUSED)
def test_parse_plan_refusals(text, prefix):
    with pytest.raises(PlanError) as e:
        parse_plan(text, SCHEMA)
    message = str(e.value)
    assert message.startswith(prefix)
    # the message names the step, never what the model wrote there
    assert not any(leak in message for leak in ("zzleak", "98765", "__import__"))


@pytest.mark.parametrize("filler", [" ", "a", "\n", "`", "``"])
def test_a_hostile_answer_is_refused_in_linear_time(filler):
    started = time.perf_counter()
    with pytest.raises(PlanError):
        parse_plan("```" + filler * 40_000, SCHEMA)
    assert time.perf_counter() - started < 1.0  # a backtracking pattern needs seconds here


def test_prompt_has_no_real_values():
    header = ["client", "contact", "revenue", "qty", "day", "paid"]
    rows = [
        ["Initech Holdings", "olga.ivanova@initech.example", "48213.57", "7731", "2026-03-14", "true"],
        ["Umbrella GmbH", "kurt.weber@umbrella.example", "9150.10", "15902", "2026-04-02", "false"],
        ["Hooli Labs", "", "20077.95", "31337", "2026-05-30", "true"],
    ]
    schema = infer_schema(header, rows)
    prompt = plan_prompt("find the top 10 clients by margin", schema)
    assert "find the top 10 clients by margin" in prompt
    for name, kind in zip(header, ("text", "text", "float", "int", "date", "bool")):
        assert f'"{name}" ({kind})' in prompt
    real = {cell for row in rows for cell in row if cell} - {"true", "false"}  # a bool has no values to hide
    assert [cell for cell in real if cell in prompt] == []
    assert "987654" not in plan_prompt("t", TableSchema([Column("a", "text")], rows=987654))  # the table size stays home too
    # the made-up rows are the ones synthetic_rows gives, and examples=0 leaves them out
    assert all(",".join(row) in prompt for row in synthetic_rows(schema, 3))
    assert len(plan_prompt("t", schema, examples=5).splitlines()) - len(prompt.splitlines()) == 2
    assert "Made-up" not in plan_prompt("t", schema, examples=0)


def test_prompt_depends_on_names_types_and_task_only():
    header = ["client", "amount"]
    a = infer_schema(header, [["Acme", "10.5"], ["Globex", "99"]])
    b = infer_schema(header, [["Initech", "1.5"]] * 7)
    assert plan_prompt("t", a) == plan_prompt("t", b)
    assert plan_prompt("t", a) != plan_prompt("t", infer_schema(["client", "amount"], [["Acme", "x"]]))  # another type, another prompt


def test_prompt_quotes_column_names():
    schema = TableSchema([Column('a"b\nc', "text"), Column("Клиент, ₽", "float")], rows=1)
    prompt = plan_prompt("t", schema)
    assert '- "a\\"b\\nc" (text)' in prompt
    assert '- "Клиент, ₽" (float)' in prompt
    assert '"a""b\nc","Клиент, ₽"' in prompt  # the example header is CSV


def test_prompt_states_the_grammar_and_its_example_is_valid():
    prompt = plan_prompt("t", SCHEMA)
    assert prompt == plan_prompt("t", SCHEMA) and prompt.isascii()  # same prompt every time; hyphens and straight quotes only
    for op in ("filter", "derive", "group", "sort", "limit", "select", "chart"):
        assert f'{{"op": "{op}"' in prompt
    for word in ("==", "!=", ">=", "<=", "contains", "sum", "mean", "count", "min", "max", "bar", "line", "pie", "1 to 50 steps", "from 1 to 10000", "1 to 20 aggregates", "1 to 64"):
        assert word in prompt
    example = next(line for line in prompt.splitlines() if line.startswith('{"version": 1'))
    assert len(parse_plan(example, SCHEMA).steps) >= 4
    header, rows = ["client", "revenue", "cost"], [["Acme", "10.5", "4"], ["Beta", "7", "9.5"], ["Acme", "3", "1"]]
    result = run_plan(parse_plan(example, infer_schema(header, rows)), header, rows)
    assert result.rows == [["Acme", 8.5], ["Beta", -2.5]] and result.chart["points"] == result.rows


def run(steps, header, rows):
    return run_plan(parse_plan(plan(*steps), infer_schema(header, rows)), header, rows)


def test_top_clients_by_margin():
    cents = [(f"Client {i * 7 % 41:02d}", 10_000 + i * 7919 % 90_000, 1_000 + i * 104_729 % 60_000) for i in range(3000)]

    def money(c):
        return f"{c // 100}.{c % 100:02d}"

    rows = [[client, money(revenue), money(cost)] for client, revenue, cost in cents]
    totals = {}
    for client, revenue, cost in cents:
        totals[client] = totals.get(client, 0) + revenue - cost
    expected = sorted(totals.items(), key=lambda item: -item[1])[:11]
    assert len({total for _, total in expected}) == 11  # no tie at the cut: the order is unambiguous
    result = run(TOP10, ["client", "revenue", "cost"], rows)
    assert result.header == ["client", "total"] and result.chart is None
    assert [row[0] for row in result.rows] == [client for client, _ in expected[:10]]
    assert [row[1] for row in result.rows] == pytest.approx([total / 100 for _, total in expected[:10]], abs=1e-6)


def test_filter_and_chart_spec():
    header = ["client", "region", "revenue", "paid", "day"]
    rows = [
        ["Acme", "EU", "100.5", "true", "2026-01-10"],
        ["Acme", "EU", "50", "true", "2026-02-10"],
        ["Beta", "US", "300", "false", "2026-02-11"],
        ["Beta", "US", "75.25", "true", "2026-03-01"],
        ["Cora", "EU", "20", "true", "2026-03-02"],
        ["Dyno", "", "900", "true", "2026-03-03"],
    ]
    steps = [
        flt(column="paid", cmp="==", value=True),
        flt(column="day", cmp=">=", value="2026-02-01"),
        group(by=["region"], aggregates={"total": ["sum", "revenue"], "orders": ["count", "client"]}),
        sort(by=["total"], desc=True),
        chart(x="region", y="total"),
    ]
    result = run(steps, header, rows)
    assert result.header == ["region", "total", "orders"]
    assert result.rows == [[None, 900.0, 1], ["US", 75.25, 1], ["EU", 70.0, 2]]  # an empty region is a group of its own
    # a point needs both values, so the group without a region is not drawn
    assert result.chart == {"kind": "bar", "x": "region", "y": "total", "points": [["US", 75.25], ["EU", 70.0]]}
    assert run([chart(x="client", y="revenue", kind="pie")], header, rows).chart["kind"] == "pie"
    holes = run([chart(kind="line", x="day", y="revenue")], ["day", "revenue"], [["2026-01-01", "5"], ["2026-01-02", ""], ["", "7"], ["2026-01-04", "8.5"]])
    assert holes.chart["points"] == [["2026-01-01", 5.0], ["2026-01-04", 8.5]]


def test_text_cells_keep_their_spaces():
    assert run([flt(column="t", cmp="==", value="Acme")], ["t"], [[" Acme "], ["Acme"], ["  "]]).rows == [["Acme"]]
    assert run([limit()], ["t"], [[" Acme "], ["  "]]).rows == [[" Acme "], [None]]


CMP_HEADER = ["name", "qty", "price", "day", "ok"]
CMP_ROWS = [
    ["Alpha Corp", " 1 ", "1.5 ", " 2026-01-01 ", " true"],  # padding is not part of a number, a date or a bool
    ["beta corp", "5", "2.5", "2026-06-15", "false"],
    ["Gamma", "10", "2.5", "2027-01-01", ""],
    ["", "", "", "", "true"],
]


@pytest.mark.parametrize(
    ("column", "cmp", "value", "names"),
    [
        ("name", "contains", "Corp", ["Alpha Corp"]),  # case-sensitive
        ("name", "contains", "", ["Alpha Corp", "beta corp", "Gamma"]),
        ("name", "==", "Gamma", ["Gamma"]),
        ("name", "!=", "Gamma", ["Alpha Corp", "beta corp"]),  # an empty cell matches nothing, != included
        ("qty", ">", 1, ["beta corp", "Gamma"]),
        ("qty", ">=", 5, ["beta corp", "Gamma"]),
        ("qty", "<", 5, ["Alpha Corp"]),
        ("qty", "<=", 5, ["Alpha Corp", "beta corp"]),
        ("qty", "==", 5.0, ["beta corp"]),
        ("qty", ">", 4.5, ["beta corp", "Gamma"]),
        ("price", "==", 2.5, ["beta corp", "Gamma"]),
        ("day", "<", "2026-12-31", ["Alpha Corp", "beta corp"]),
        ("day", "==", "2027-01-01", ["Gamma"]),
        ("day", "==", "2026-01-01", ["Alpha Corp"]),
        ("ok", "==", False, ["beta corp"]),
        ("ok", "!=", False, ["Alpha Corp", None]),
    ],
)
def test_every_comparison(column, cmp, value, names):
    result = run([flt(column=column, cmp=cmp, value=value)], CMP_HEADER, CMP_ROWS)
    assert [row[0] for row in result.rows] == names


def test_empty_cells_are_skipped_not_guessed():
    header = ["k", "v"]
    rows = [["a", "1"], ["a", ""], ["b", ""], ["", "4"], ["b", "2"], ["a", "3"], ["c", ""]]
    aggregates = {"sum": ["sum", "v"], "mean": ["mean", "v"], "n": ["count", "v"], "lo": ["min", "v"], "hi": ["max", "v"]}
    result = run([group(by=["k"], aggregates=aggregates)], header, rows)
    assert result.header == ["k", "sum", "mean", "n", "lo", "hi"]
    assert result.rows == [  # groups in the order they first appear
        ["a", 4, 2.0, 2, 1, 3],
        ["b", 2, 2.0, 1, 2, 2],
        [None, 4, 4.0, 1, 4, 4],
        ["c", None, None, 0, None, None],
    ]
    assert [row[1] for row in run([sort(by=["v"], desc=False)], header, rows).rows] == [1, 2, 3, 4, None, None, None]
    assert [row[1] for row in run([sort(by=["v"], desc=True)], header, rows).rows] == [4, 3, 2, 1, None, None, None]


def test_sort_by_several_columns():
    header = ["g", "n"]
    rows = [["b", "2"], ["a", "3"], ["b", "1"], ["a", "1"], ["a", "2"], ["", "9"]]
    ascending = run([sort(by=["g", "n"], desc=False)], header, rows)
    assert [tuple(row) for row in ascending.rows] == [("a", 1), ("a", 2), ("a", 3), ("b", 1), ("b", 2), (None, 9)]
    descending = run([sort(by=["g", "n"], desc=True)], header, rows)
    assert [tuple(row) for row in descending.rows] == [("b", 2), ("b", 1), ("a", 3), ("a", 2), ("a", 1), (None, 9)]


def test_totals_select_and_limit():
    header = ["a", "b", "c"]
    rows = [["1", "x", "2.5"], ["2", "y", "3.5"], ["3", "z", "4.5"]]
    totals = run([group(by=[], aggregates={"n": ["count", "a"], "sum": ["sum", "c"]})], header, rows)
    assert (totals.header, totals.rows) == (["n", "sum"], [[3, 10.5]])
    nothing = run([flt(column="a", cmp=">", value=9), group(by=[], aggregates={"n": ["count", "a"]})], header, rows)
    assert (nothing.header, nothing.rows) == (["n"], [[0]])  # the one row of totals, as the prompt promises
    picked = run([select(["c", "a"]), limit(2)], header, rows)
    assert (picked.header, picked.rows) == (["c", "a"], [[2.5, 1], [3.5, 2]])
    assert run([limit(10000)], header, rows).rows == [[1, "x", 2.5], [2, "y", 3.5], [3, "z", 4.5]]


def test_totals_of_no_rows_are_one_row_of_zero_and_empty_cells():
    header, rows = ["a", "c"], [["1", "2.5"], ["2", "3.5"]]
    aggregates = {"n": ["count", "a"], "sum": ["sum", "c"], "mean": ["mean", "c"], "lo": ["min", "c"], "hi": ["max", "a"]}
    nothing = flt(column="a", cmp=">", value=9)
    result = run([nothing, group(by=[], aggregates=aggregates)], header, rows)
    assert (result.header, result.rows) == (["n", "sum", "mean", "lo", "hi"], [[0, None, None, None, None]])
    # with a column to group by, no rows still means no groups
    assert run([nothing, group(by=["a"], aggregates={"n": ["count", "c"]})], header, rows).rows == []
    # a table without rows reads as text everywhere, and a count of it is 0
    assert run([group(by=[], aggregates={"n": ["count", "a"]})], header, []).rows == [[0]]


def test_division_by_zero_is_null():
    header = ["a", "b"]
    rows = [["10", "2"], ["10", "0"], ["", "5"], ["7", ""], ["3", "0.0"]]
    steps = [
        {"op": "derive", "name": "q", "left": "a", "operator": "/", "right": "b"},
        {"op": "derive", "name": "z", "left": "a", "operator": "/", "right": 0},
        {"op": "derive", "name": "s", "left": "a", "operator": "+", "right": "b"},
    ]
    result = run(steps, header, rows)
    assert result.header == ["a", "b", "q", "z", "s"]
    assert [row[2] for row in result.rows] == [5.0, None, None, None, None]
    assert [row[3] for row in result.rows] == [None] * 5
    assert [row[4] for row in result.rows] == [12.0, 10.0, None, None, 3.0]
    assert [row[2] for row in run(steps[:1], ["a", "b"], [["7", "2"]]).rows] == [3.5]  # int / int is a true division


LONGEST = 999_999_999_999_999  # the longest whole number a cell may hold: 15 digits
EDGE = (2**1024 - 1) // LONGEST  # LONGEST * EDGE has 1024 bits, the most a table holds, and is too big for a float


def test_ints_stay_exact_and_huge_numbers_never_crash():
    header = ["f", "n"]
    rows = [["1" + "0" * 308 + ".0", str(LONGEST)]]  # 1e308 is a float, the other cell an int
    steps = [
        derive(name="square", left="n", operator="*", right="n"),
        derive(name="edge", left="n", operator="*", right=EDGE),
        derive(name="twice", left="edge", operator="*", right=2),  # 1025 bits: no number a table holds
        derive(name="third", left="edge", operator="/", right=3),
        derive(name="mixed", left="edge", operator="*", right=1.5),  # the int does not fit a float
        derive(name="past", left="n", operator="*", right=10**400),  # a plan may name any whole number
        derive(name="overflow", left="f", operator="*", right=10),
        derive(name="tenth", left="f", operator="/", right=10),
    ]
    [row] = run(steps, header, rows).rows
    edge = LONGEST * EDGE
    assert edge.bit_length() == 1024 and row[2] == LONGEST**2 and type(row[2]) is int
    assert row[3] == edge and type(row[3]) is int
    assert row[4] is None
    assert row[5] == pytest.approx(edge / 3)  # int / int is a true division
    assert row[6:10] == [None, None, None, pytest.approx(1e307)]
    edges = [[str(LONGEST)]] * 3
    aggregates = {"s": ["sum", "edge"], "m": ["mean", "edge"], "hi": ["max", "edge"]}
    sums = run([steps[1], group(by=[], aggregates=aggregates)], ["n"], edges).rows
    assert sums == [[None, None, edge]]  # max hands back what the cell holds, a sum and a mean are computed
    twice = [["1" + "0" * 308 + ".0"]] * 2
    aggregates = {"s": ["sum", "f"], "m": ["mean", "f"], "hi": ["max", "f"]}
    assert run([group(by=[], aggregates=aggregates)], ["f"], twice).rows == [[None, None, 1e308]]
    exact = run([group(by=[], aggregates={"s": ["sum", "n"]})], ["n"], [[str(LONGEST)]] * 10 + [["1"]]).rows
    assert exact == [[9999999999999991]] and type(exact[0][0]) is int  # a float sum gives ...992
    tenths = run([group(by=[], aggregates={"s": ["sum", "x"]})], ["x"], [["0.1"]] * 10).rows
    assert tenths == [[1.0]]  # money adds up to the cent: a plain float sum gives 0.9999999999999999


def test_repeated_squaring_cannot_blow_up():
    # the digits double with every step; an unbounded int would take all the memory long before 50 steps
    steps = [derive(name="x2", left="x", operator="*", right="x")]
    steps += [derive(name=f"x{2**k}", left=f"x{2 ** (k - 1)}", operator="*", right=f"x{2 ** (k - 1)}") for k in range(2, 15)]
    [row] = run(steps, ["x"], [["123456789"]]).rows
    assert row[1] == 123456789**2 and row[3] == 123456789**8  # exact while it fits
    assert row[-1] is None


def test_run_plan_refuses_a_plan_that_does_not_fit_the_rows():
    header, rows = ["qty", "name"], [["1", "a"], ["2", "b"]]
    for steps in (
        [{"op": "filter", "column": "nope", "cmp": "==", "value": 1}],
        [limit(), limit() | {"extra": 1}],
        [flt(value=float("inf"))],
        [flt(value=float("nan"))],
        [flt(column="name")],  # the table decides, not whoever built the plan
        [flt(column="name", cmp="==", value="\ud800")],  # a value that no file can hold
        [limit(10**9)],
        [],
        "limit",
    ):
        with pytest.raises(PlanError):
            run_plan(Plan(steps=steps), header, rows)
    parsed = parse_plan(plan(flt()), infer_schema(["qty"], [["1"], ["2"]]))
    with pytest.raises(PlanError, match="step 1: "):
        run_plan(parsed, ["qty"], [["x"], ["2"]])
    with pytest.raises(PlanError, match="same name"):
        run_plan(Plan(steps=[limit()]), ["a", "a"], [])
    with pytest.raises(PlanError, match="row 1 "):
        run_plan(Plan(steps=[limit()]), ["a"], [["1", "2"]])


def test_the_cell_limit_is_five_million():
    assert boxed.opplan.MAX_CELLS == 5_000_000


def test_a_table_over_the_cell_limit_is_refused_before_any_work():
    rows = [["1"]] * 5_000_001  # one row repeated: over the limit, and not a cell of it is looked at
    for work in (lambda: infer_schema(["a"], rows), lambda: run_plan(Plan(steps=[limit()]), ["a"], rows)):
        started = time.perf_counter()
        with pytest.raises(PlanError, match="cells") as e:
            work()
        assert time.perf_counter() - started < 1.0 and "5000001" not in str(e.value)


def test_a_header_over_the_cell_limit_is_refused_though_the_table_has_no_rows():
    header = ["a"] * 5_000_001  # not even the names are compared first
    for work in (lambda: infer_schema(header, []), lambda: run_plan(Plan(steps=[limit()]), header, [])):
        with pytest.raises(PlanError, match="cells"):
            work()


def test_the_cell_limit_counts_rows_times_columns(monkeypatch):
    monkeypatch.setattr(boxed.opplan, "MAX_CELLS", 6)
    header = ["a", "b"]
    assert run_plan(Plan(steps=[limit()]), header, [["1", "2"]] * 3).rows == [[1, 2]] * 3  # 6 cells: allowed
    assert run_plan(Plan(steps=[limit()]), header, []).rows == []
    with pytest.raises(PlanError, match="cells"):
        run_plan(Plan(steps=[limit()]), header, [["1", "2"]] * 4)  # 8 cells
    assert infer_schema(list("abcdef"), []).rows == 0  # a table without rows counts as one row: 6 cells
    with pytest.raises(PlanError, match="cells"):
        infer_schema(list("abcdefg"), [])  # 7


def aggregates(count, column="revenue"):
    return {f"a{i}": ["sum", column] for i in range(count)}


def test_a_plan_makes_at_most_50_new_columns():
    # every derive step and every aggregate makes a column: 20 + 20 + 10 is the most a plan may make
    fifty = [group(aggregates=aggregates(20)), group(aggregates=aggregates(20, "a0"))]
    fifty += [derive(name=f"d{i}", left="a0", operator="+", right=i) for i in range(10)]
    assert parse_plan(plan(*fifty), SCHEMA).steps == fifty
    over = [*fifty, derive(name="zzleak", left="a0", operator="+", right=10)]  # the 51st
    refusals = [
        lambda: parse_plan(plan(*over), SCHEMA),
        lambda: run_plan(Plan(steps=over), ["client", "revenue"], [["a", "1"], ["b", "2"]]),
    ]
    for refuse in refusals:
        with pytest.raises(PlanError, match="^step 13: ") as e:
            refuse()
        assert "50" in str(e.value) and "zzleak" not in str(e.value)
    groups = [group(aggregates=aggregates(20)), group(aggregates=aggregates(20, "a0")), group(aggregates=aggregates(20, "a0"))]
    with pytest.raises(PlanError, match="^step 3: "):  # aggregates count like derived columns
        parse_plan(plan(*groups), SCHEMA)


def test_prompt_states_the_new_column_limit():
    assert "at most 50 new columns" in plan_prompt("t", SCHEMA)


def test_prompt_states_the_cell_limit_of_every_step():
    prompt = plan_prompt("t", SCHEMA)
    assert f"at most {boxed.opplan.MAX_CELLS} cells (rows times columns)" in prompt
    assert "5000000" in prompt and "filter or limit before" in prompt
    assert "3000" not in prompt  # the limit is a constant of the grammar; the size of this table stays home


def test_a_derive_that_takes_the_table_past_the_cell_limit_is_refused(monkeypatch):
    monkeypatch.setattr(boxed.opplan, "MAX_CELLS", 12)
    header, rows = ["a", "b"], [["1", "2"], ["3", "4"], ["5", "6"]]  # 6 cells
    more = [derive(name=name, left="a", operator="+", right="b") for name in ("c", "d", "zzleak")]
    assert run(more[:2], header, rows).header == ["a", "b", "c", "d"]  # 3 rows times 4 columns: 12 cells, the limit
    with pytest.raises(PlanError, match="^step 3: ") as e:
        run(more, header, rows)  # 15
    assert "cells" in str(e.value) and "15" not in str(e.value) and "zzleak" not in str(e.value)


def test_the_cell_budget_counts_the_rows_that_earlier_steps_left(monkeypatch):
    monkeypatch.setattr(boxed.opplan, "MAX_CELLS", 12)
    header, rows = ["a", "b"], [["1", "2"], ["3", "4"], ["5", "6"]]
    derives = [derive(name=f"c{i}", left="a", operator="+", right="b") for i in range(5)]
    with pytest.raises(PlanError, match="^step 3: "):
        run(derives, header, rows)  # 3 rows times 5 columns
    assert run([flt(column="a", cmp=">", value=4), *derives], header, rows).rows == [[5, 6, 11, 11, 11, 11, 11]]  # one row left


def test_a_group_that_takes_the_table_past_the_cell_limit_is_refused(monkeypatch):
    monkeypatch.setattr(boxed.opplan, "MAX_CELLS", 12)
    header = ["k", "v"]
    wide = group(by=["k"], aggregates={"s": ["sum", "v"], "n": ["count", "v"], "zzleak": ["max", "v"]})  # 4 columns
    with pytest.raises(PlanError, match="^step 1: ") as e:
        run([wide], header, [["a", "1"], ["b", "2"], ["c", "3"], ["d", "4"]])  # 4 groups times 4 columns: 16 cells
    assert "cells" in str(e.value) and "16" not in str(e.value) and "zzleak" not in str(e.value)
    assert len(run([wide], header, [["a", "1"], ["a", "2"], ["b", "3"], ["b", "4"]]).rows) == 2  # 2 groups: 8 cells


def test_a_group_may_have_as_many_cells_as_the_limit_allows(monkeypatch):
    monkeypatch.setattr(boxed.opplan, "MAX_CELLS", 12)
    wide = group(by=["k"], aggregates={"s": ["sum", "v"], "n": ["count", "v"], "m": ["max", "v"]})  # 4 columns
    rows = [["a", "1"], ["b", "2"], ["c", "3"], ["a", "4"], ["b", "5"], ["c", "6"]]
    assert len(run([wide], ["k", "v"], rows).rows) == 3  # 3 groups times 4 columns: 12 cells, the limit


def test_a_group_step_stops_reading_rows_once_its_groups_pass_the_cell_limit(monkeypatch):
    monkeypatch.setattr(boxed.opplan, "MAX_CELLS", 12)

    class Unread(list):
        def __getitem__(self, at):
            raise AssertionError("the group step went on reading rows after the limit")

    step = group(by=["k"], aggregates={"s": ["sum", "v"], "n": ["count", "v"], "m": ["max", "v"]})  # 4 columns: 3 groups at most
    table = [["a", 1], ["b", 2], ["c", 3], ["d", 4], Unread(["e", 5]), Unread(["f", 6])]  # the fourth group is one too many
    with pytest.raises(PlanError, match="^step 1: ") as e:
        boxed.opplan._group_rows(1, ["k", "v"], table, step)
    assert "cells" in str(e.value)


def test_running_a_plan_changes_nothing_it_was_given():
    header, rows = ["a", "b"], [["1", "2"], ["3", "4"]]
    parsed = parse_plan(plan(select(["a", "b"]), derive(name="c", left="a", right="b", operator="+"), sort(by=["c"], desc=True)), infer_schema(header, rows))
    before = (copy.deepcopy(parsed), list(header), [row[:] for row in rows])
    result = run_plan(parsed, header, rows)
    assert result.header == ["a", "b", "c"] and result.rows == [[3, 4, 7], [1, 2, 3]]
    assert (parsed, header, rows) == before


def test_plan_strings_are_data_not_code():
    code = "__import__('builtins').zzpwned = 1"
    result = run([flt(column="t", cmp="contains", value=code)], ["t"], [[code], ["plain"]])
    assert result.rows == [[code]] and not hasattr(builtins, "zzpwned")


def test_executor_never_evaluates_text():
    tree = ast.parse(Path(boxed.opplan.__file__).read_text())
    called = {n.func.id for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
    assert called.isdisjoint({"eval", "exec", "compile", "__import__", "open", "getattr", "setattr", "globals", "locals", "vars", "input"})
    imported = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    imported |= {n.module.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    assert imported <= {"csv", "io", "json", "math", "operator", "random", "re", "string", "dataclasses", "datetime", "errors"}  # errors: boxed.errors


FUZZ_HEADER = ["name", "qty", "price", "day", "ok"]
FUZZ_ROWS = [
    ["Alpha", "1", "1.5", "2026-01-01", "true"],
    ["Beta", "", "2.5", "2026-06-15", "false"],
    ["", "10", "", "", ""],
    ["Alpha", "7", "0", "2027-01-01", "true"],
]
CATALOG = [
    flt(column="name", cmp="contains", value="a"),
    flt(column="name", cmp="!=", value="Alpha"),
    flt(column="qty", cmp=">", value=1),
    flt(column="price", cmp="<=", value=2.5),
    flt(column="day", cmp=">=", value="2026-06-15"),
    flt(column="ok", cmp="==", value=True),
    flt(column="m", cmp=">", value=0),
    flt(column="total", cmp=">=", value=1),
    derive(name="m", left="qty", operator="-", right="price"),
    derive(name="r", left="price", operator="/", right="qty"),
    derive(name="k", left="qty", operator="*", right=3),
    group(by=["name"], aggregates={"total": ["sum", "qty"], "n": ["count", "day"], "hi": ["max", "day"]}),
    group(by=[], aggregates={"total": ["sum", "qty"], "avg": ["mean", "price"]}),
    group(by=["ok", "name"], aggregates={"total": ["mean", "price"]}),
    sort(by=["name"], desc=True),
    sort(by=["qty", "price"], desc=False),
    sort(by=["total"], desc=True),
    limit(2),
    limit(10000),
    select(["name", "qty"]),
    select(["total", "name"]),
    chart(x="name", y="qty"),
    chart(x="name", y="total"),
]
JUNK = [None, True, 0, -1, 10**6, 1.5, "", "zz", "name", "qty", "2026-13-45", ["name"], [], {}]


@st.composite
def fuzzed_steps(draw):
    steps = [dict(step) for step in draw(st.lists(st.sampled_from(CATALOG), min_size=1, max_size=6))]
    if draw(st.booleans()):
        step = draw(st.sampled_from(steps))
        step[draw(st.sampled_from(sorted(step)))] = draw(st.sampled_from(JUNK))
    return steps


@settings(max_examples=800, deadline=None)
@given(fuzzed_steps())
def test_any_plan_is_refused_or_runs_cleanly(steps):
    try:
        parsed = parse_plan(plan(*steps), infer_schema(FUZZ_HEADER, FUZZ_ROWS))
    except PlanError:
        event("refused")
        return
    event("ran")
    before = (copy.deepcopy(parsed), list(FUZZ_HEADER), [row[:] for row in FUZZ_ROWS])
    result = run_plan(parsed, FUZZ_HEADER, FUZZ_ROWS)
    assert (parsed, FUZZ_HEADER, FUZZ_ROWS) == before
    assert len(set(result.header)) == len(result.header)
    for row in result.rows:
        assert len(row) == len(result.header)
        assert all(v is None or type(v) in (int, float, str, bool) for v in row)
        assert all(math.isfinite(v) for v in row if type(v) is float)
    if result.chart:
        assert len(result.chart["points"]) <= len(result.rows)


def test_prompt_refuses_a_header_that_looks_like_data():
    header, rows = ["ivan", "1500", "2026-10-01"], [["anna", "200", "2026-10-02"]]
    schema = infer_schema(header, rows)
    assert data_like_header(header) == ["1500", "2026-10-01"]
    with pytest.raises(PlanError, match="header"):
        plan_prompt("top clients", schema)
    assert "1500" in plan_prompt("top clients", schema, header_confirmed=True)


@pytest.mark.parametrize(
    "cell",
    [
        "40817810099910004312",  # a bank account: 20 digits, and no detector knows it
        "12345678901234567890",
        "4081 7810 0999 1000 4312",
        "1E5",  # the exponent forms that are text as a column but numbers in a header
        "1e5",
        "2.5E-3",
        "1e999",
        "-12",
        "+7",
        "007",
        "1 234,50",
        "1\u00a0234,50",  # a no-break space and a narrow one, as exports write the groups
        "1\u202f234,50",
        "1,234.56",
        "1'234.50",
        ".5",
        "5.",
        "12.10.2026",
    ],
)
def test_a_header_cell_that_is_a_number_in_any_writing_looks_like_data(cell):
    assert data_like_header(["client", cell, "region"]) == [cell]
    assert data_like_header([f" {cell} "]) == [f" {cell} "]  # padding does not hide it


@pytest.mark.parametrize("name", ["client", "Q1", "revenue 2026", "10%", "1C", "id", "e5", "E", "a.b", "-", "+", ".", ",", ""])
def test_ordinary_column_names_do_not_look_like_data(name):
    assert data_like_header([name]) == []


@pytest.mark.parametrize(
    "first_row",
    [
        ["40817810099910004312", "Ivan", "Moscow"],  # a headerless table that starts with an account number
        ["1E5", "Ivan", "Moscow"],
        ["12345678901234567890", "Ivan", "Moscow"],
    ],
    ids=["account", "exponent", "long id"],
)
def test_prompt_refuses_a_first_row_that_is_numbers_in_any_writing(first_row):
    schema = infer_schema(first_row, [["x", "Anna", "Kazan"]])
    with pytest.raises(PlanError, match="header") as e:
        plan_prompt("top clients", schema)
    assert first_row[0] not in str(e.value)  # the refusal names no value
    assert first_row[0] in plan_prompt("top clients", schema, header_confirmed=True)  # the person may confirm it


def test_russian_export_normalised_before_inference():
    header = ["client", "revenue", "day"]
    rows = [["Ромашка", "1 234,50", "21.10.2026"], ["Лютик", "99,5", "01.02.2026"]]
    assert guess_decimal(rows) == ","
    clean = normalize_rows(rows, decimal=",")
    schema = infer_schema(header, clean)
    assert [c.type for c in schema.columns] == ["text", "float", "date"]
    plan = parse_plan('{"version": 1, "steps": [{"op": "sort", "by": ["revenue"], "desc": true}]}', schema)
    assert run_plan(plan, header, clean).rows[0][1:] == [1234.5, "2026-10-21"]


def test_ambiguous_thousands_stay_text():
    rows = [["a", "1,234"], ["b", "2,500"]]
    assert guess_decimal(rows) == "." and normalize_rows(rows) == rows
    assert normalize_rows([["1 234 567", "1 234.5"]]) == [["1234567", "1234.5"]]


# --- normalising only what a plan reads, and not before the table is known to fit ---


def reference_guess_decimal(rows):
    """guess_decimal as it was before it learned to stop early: every cell, with the spaces taken out first."""
    comma = point = False
    for row in rows:
        for cell in row:
            s = re.sub(boxed.opplan._SPACES, "", cell.strip())
            comma = comma or bool(boxed.opplan._COMMA_EVIDENCE.fullmatch(s))
            point = point or bool(boxed.opplan._POINT_EVIDENCE.fullmatch(s))
    return "," if comma and not point else "."


def reference_normalize_cell(cell, decimal):
    """One cell as normalize_rows treated it before it skipped cells that cannot be numbers."""
    number = boxed.opplan._GROUPED_COMMA if decimal == "," else boxed.opplan._GROUPED_POINT
    s = cell.strip()
    if m := boxed.opplan._DMY.fullmatch(s):
        iso = f"{m[3]}-{m[2]}-{m[1]}"
        return iso if boxed.opplan._is_date(iso) else cell
    if number.fullmatch(s):
        return re.sub(boxed.opplan._SPACES, "", s).replace(",", ".")
    return cell


SPACES = " \u00a0\u202f"
GROUPS = st.one_of(  # "1 234 567" as an export writes it, and digit runs of any length
    st.builds(lambda first, rest: [str(first), *map("{:03d}".format, rest)], st.integers(0, 999), st.lists(st.integers(0, 999), max_size=2)),
    st.lists(st.integers(0, 99999).map(str), min_size=1, max_size=3),
)
NUMBERISH = st.builds(
    lambda sign, groups, space, tail: sign + space.join(groups) + tail,
    st.sampled_from(["", "-"]),
    GROUPS,
    st.sampled_from(list(SPACES)),
    st.sampled_from(["", ",", ".", ",5", ".5", ",50", ".25", ",123", ",1234"]),
)
DATEISH = st.builds("{:02d}.{:02d}.{:04d}".format, st.integers(0, 40), st.integers(0, 14), st.integers(1990, 2100))
ANYTHING = st.text(alphabet="0123456789 ,.-+eEx\u00a0\u202f\t\n", max_size=12)
PADDED = st.builds("".join, st.tuples(st.sampled_from(["", " ", "\u00a0", "\t"]), st.one_of(NUMBERISH, DATEISH), st.sampled_from(["", " ", "\n"])))
EXPORT_CELLS = st.one_of(NUMBERISH, DATEISH, ANYTHING, PADDED)
EXPORT_TABLES = st.lists(st.lists(EXPORT_CELLS, max_size=5), max_size=6)  # ragged rows included: the table is not checked yet


@settings(max_examples=600, deadline=None)
@given(EXPORT_TABLES)
def test_guess_decimal_guesses_what_it_guessed_before(rows):
    assert guess_decimal(rows) == reference_guess_decimal(rows)


@settings(max_examples=600, deadline=None)
@given(EXPORT_TABLES, st.sampled_from([".", ","]))
def test_normalize_rows_gives_what_it_gave_before(rows, decimal):
    assert normalize_rows(rows, decimal) == [[reference_normalize_cell(cell, decimal) for cell in row] for row in rows]


@settings(max_examples=300, deadline=None)
@given(EXPORT_TABLES, st.sampled_from([".", ","]), st.sets(st.integers(0, 6)))
def test_normalize_rows_with_columns_changes_those_columns_only(rows, decimal, columns):
    before = [row[:] for row in rows]
    got = normalize_rows(rows, decimal, columns=columns)
    assert rows == before  # the input is not touched
    assert got == [[reference_normalize_cell(c, decimal) if i in columns else c for i, c in enumerate(row)] for row in rows]


class Counting:
    """A compiled pattern that counts the cells it is asked about."""

    def __init__(self, pattern):
        self.pattern, self.calls = pattern, 0

    def fullmatch(self, text):
        self.calls += 1
        return self.pattern.fullmatch(text)


def count_pattern_matches(monkeypatch):
    names = ("_POINT_EVIDENCE", "_COMMA_EVIDENCE", "_DMY", "_GROUPED_POINT", "_GROUPED_COMMA")
    spies = {name: Counting(getattr(boxed.opplan, name)) for name in names}
    for name, spy in spies.items():
        monkeypatch.setattr(boxed.opplan, name, spy)
    return lambda: sum(spy.calls for spy in spies.values())


def test_words_are_not_matched_against_the_number_patterns(monkeypatch):
    calls = count_pattern_matches(monkeypatch)
    rows = [["Acme Corp", "Beta"], ["", "  "], ["+7 999 123", "x 1,5"], ["n/a", "#REF!"]]
    assert guess_decimal(rows) == "."
    assert normalize_rows(rows, ",") == rows == normalize_rows(rows, ".")
    assert calls() == 0


def test_guess_decimal_stops_at_the_first_decimal_point(monkeypatch):
    point = Counting(boxed.opplan._POINT_EVIDENCE)
    monkeypatch.setattr(boxed.opplan, "_POINT_EVIDENCE", point)
    assert guess_decimal([["Acme", "1.5"], ["Beta", "2,5"], ["Cora", "3.5"]]) == "."  # a point settles it, whatever follows
    assert point.calls == 1


def test_normalize_rows_with_columns_leaves_the_other_columns_as_they_are():
    rows = [["1 234,50", "1 234,50", "21.10.2026"], ["99,5"]]  # the second row is short
    assert normalize_rows(rows, ",", columns={0}) == [["1234.50", "1 234,50", "21.10.2026"], ["99.5"]]
    assert normalize_rows(rows, ",", columns=[0, 2]) == [["1234.50", "1 234,50", "2026-10-21"], ["99.5"]]
    assert normalize_rows(rows, ",", columns={1, 5}) == [["1 234,50", "1234.50", "21.10.2026"], ["99,5"]]  # no cell 5, no short row cell 1
    assert normalize_rows(rows, ",", columns=set()) == rows
    assert normalize_rows(rows, ",", columns=None) == normalize_rows(rows, ",")


def test_a_table_over_the_cell_limit_is_refused_before_a_cell_is_normalised():
    rows = [["1", "2,5"]] * 3_000_000  # 6 million cells in one repeated row: nothing to hold in memory, and the limit is 5 million
    for work in (lambda: guess_decimal(rows), lambda: normalize_rows(rows), lambda: normalize_rows(rows, ",", columns={1})):
        started = time.perf_counter()
        with pytest.raises(PlanError, match="cells") as e:
            work()
        assert time.perf_counter() - started < 1.0 and "6000000" not in str(e.value)


def test_the_cell_limit_of_normalising_counts_every_cell(monkeypatch):
    monkeypatch.setattr(boxed.opplan, "MAX_CELLS", 6)
    assert guess_decimal([["1,5", "2"]] * 3) == "," and normalize_rows([["1 000", "2"]] * 3) == [["1000", "2"]] * 3  # 6 cells
    assert guess_decimal([]) == "." and normalize_rows([]) == []
    for work in (guess_decimal, normalize_rows):
        with pytest.raises(PlanError, match="cells"):
            work([["1", "2"]] * 3 + [["3"]])  # 7, in rows of different lengths


WIDE = ["client", "region", "revenue", "cost", "day"]


@pytest.mark.parametrize(
    ("steps", "read"),
    [
        # group and select drop every column they do not name, so those are the ones that matter
        ([derive(name="margin", left="revenue", operator="-", right="cost"), group(by=["client"], aggregates={"total": ["sum", "margin"]}), sort(by=["total"], desc=True), limit(10)], {0, 2, 3}),
        ([select(["day", "client"]), limit(3)], {0, 4}),
        ([group(by=[], aggregates={"n": ["count", "region"]})], {1}),
        ([flt(column="day", cmp=">=", value="2026-01-01"), group(by=["region"], aggregates={"total": ["sum", "revenue"]}), chart(x="region", y="total")], {1, 2, 4}),
        # a name is a name wherever it stands, so a value or a new name that equals a column is read too; other new names are no column
        ([flt(column="client", cmp="==", value="cost"), select(["client"])], {0, 3}),
        ([select(["client"]), derive(name="region", left="client", operator="+", right=1)], {0, 1}),
        ([derive(name="day2", left="revenue", operator="+", right=1), select(["day2"])], {2}),
        # nothing is dropped: every column is in the result
        ([flt(column="client", cmp="contains", value="A"), limit(5)], None),
        ([derive(name="margin", left="revenue", operator="-", right="cost"), sort(by=["margin"], desc=True)], None),
    ],
)
def test_plan_columns_are_the_columns_a_plan_reads_or_lets_through(steps, read):
    text = plan(*steps)
    assert plan_columns(text, WIDE) == read
    assert plan_columns(f"Here it is:\n```json\n{text}\n```", WIDE) == read  # a code block, as parse_plan reads it
    assert plan_columns(json.dumps(json.loads(text), indent=2), WIDE) == read


@pytest.mark.parametrize(
    "text",
    [
        pytest.param("", id="empty"),
        pytest.param("I cannot do that", id="prose"),
        pytest.param("[1]", id="array"),
        pytest.param('{"version": 1}', id="no steps"),
        pytest.param('{"version": 2, "steps": []}', id="version 2"),
        pytest.param('{"version": 1, "steps": "group"}', id="steps is a string"),
        pytest.param('{"version": 1, "steps": ["group", "select"]}', id="steps are strings"),
        pytest.param('{"version": 1, "steps": [{"op": ["group"]}]}', id="op is a list"),
        pytest.param('{"version": 1, "steps": [{"op": "group", "by": {"a": 1}}, 5]}', id="a step is a number"),
        pytest.param("[" * 50_000, id="nesting past the parser"),
        pytest.param(" " * 200_000 + plan(group(by=["client"], aggregates={"n": ["count", "client"]})), id="answer too long"),
        pytest.param("```json\n" + plan(select(["client"])), id="unterminated code block"),
    ],
)
def test_plan_columns_of_something_that_is_no_plan_are_all_of_them(text):
    assert plan_columns(text, WIDE) is None


def test_plan_columns_survive_a_deeply_nested_value():
    # nested far deeper than a recursive walk of the steps would survive: the parser may give up (all columns), nothing may be raised
    deep = f'{"[" * 800}"client"{"]" * 800}'
    text = f'{{"version": 1, "steps": [{json.dumps(select(["region"]))}, {{"op": "filter", "column": "cost", "cmp": "==", "value": {deep}}}]}}'
    assert plan_columns(text, WIDE) in ({0, 1, 3}, None)


RUSSIAN = [
    ["Alpha", "1 000", "1 234,50", "21.10.2026", "true"],
    ["Beta", "", "2,5", "15.06.2026", "false"],
    ["", "10", "", "", ""],
    ["Alpha", "7", "0", "01.01.2027", "true"],
]


def outcome(text, header, rows, decimal, columns):
    clean = normalize_rows(rows, decimal, columns=columns)
    try:
        result = run_plan(parse_plan(text, infer_schema(header, clean)), header, clean)
    except PlanError as error:
        return str(error)
    return result.header, result.rows, result.chart


@settings(max_examples=400, deadline=None)
@given(fuzzed_steps())
def test_normalising_only_what_a_plan_reads_changes_no_result_and_no_refusal(steps):
    text = plan(*steps)
    read = plan_columns(text, FUZZ_HEADER)
    assert outcome(text, FUZZ_HEADER, RUSSIAN, ",", read) == outcome(text, FUZZ_HEADER, RUSSIAN, ",", None)


def test_the_top_clients_plan_of_a_wide_russian_export_needs_three_columns():
    header = ["client", "region", "revenue", "cost", "day"]
    rows = [["Ромашка", "EU", "1 234,50", "1 000,25", "21.10.2026"], ["Лютик", "US", "99,5", "10", "22.10.2026"], ["Ромашка", "EU", "10,00", "5", "23.10.2026"]]
    text = plan(derive(name="margin", left="revenue", operator="-", right="cost"), group(by=["client"], aggregates={"total": ["sum", "margin"]}), sort(by=["total"], desc=True))
    read = plan_columns(text, header)
    assert read == {0, 2, 3}
    assert outcome(text, header, rows, ",", read) == (["client", "total"], [["Ромашка", 239.25], ["Лютик", 89.5]], None)
    assert outcome(text, header, rows, ",", read) == outcome(text, header, rows, ",", None)
