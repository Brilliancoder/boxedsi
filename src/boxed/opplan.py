"""Level 4: the model gets the task and the table schema and answers with a plan of operations; boxed runs the plan locally."""

import csv
import io
import json
import math
import random
import re
import string
from dataclasses import dataclass
from datetime import date, timedelta
from operator import add, contains, eq, ge, gt, le, lt, mul, ne, sub, truediv

from .errors import UserError, number

COLUMN_TYPES = ("int", "float", "date", "bool", "text")
MAX_STEPS = 50
MAX_LIMIT = 10000
MAX_AGGREGATES = 20
MAX_NEW_COLUMNS = 50  # in a whole plan: every derive step and every aggregate makes one
MAX_NAME = 64
MAX_PLAN_CHARS = 100_000
MAX_CELLS = 5_000_000  # rows times columns: a sort or a derive costs time and memory in proportion
MAX_DIGITS = 15  # a float holds 15 decimal digits exactly; a longer whole number is an identifier (a card, an account)

_BOOLS = ("true", "false")
# identifiers keep their form: no leading "+" or zeros, no decimal comma, no exponent, nothing but ASCII digits
_INT = re.compile(r"-?(?:0|[1-9][0-9]*)")
_FLOAT = re.compile(r"-?(?:(?:0|[1-9][0-9]*)(?:\.[0-9]*)?|\.[0-9]+)")
_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
# a number in any writing, for the check of a header: any digit count, a sign, digit groups, a decimal part, an exponent
_NUMBER_LIKE = re.compile(r"[+-]?(?:[0-9]+(?:[ \u00a0\u202f',_.][0-9]+)*[.,]?|[.,][0-9]+)(?:[eE][+-]?[0-9]+)?")
# a new column starts with a letter or digit, so a name never reads as a formula in a spreadsheet
_NAME = re.compile(rf"[^\W_][\w .%()-]{{0,{MAX_NAME - 1}}}")
_FENCE_TAG = string.ascii_letters + string.digits + "_-"  # the "json" after the opening fence

_NUMERIC = ("int", "float")
_ORDERED = ("int", "float", "date")
_CMPS = ("==", "!=", ">", ">=", "<", "<=", "contains")
_OPERATORS = ("+", "-", "*", "/")
_AGGREGATES = {"sum": _NUMERIC, "mean": _NUMERIC, "count": COLUMN_TYPES, "min": _ORDERED, "max": _ORDERED}
_CHARTS = ("bar", "line", "pie")


@dataclass(frozen=True)
class Column:
    name: str
    type: str

    def __post_init__(self) -> None:
        if self.type not in COLUMN_TYPES:
            raise ValueError(f"type must be one of {COLUMN_TYPES}, got {self.type!r}")


@dataclass
class TableSchema:
    columns: list[Column]
    rows: int


class PlanError(UserError):
    """A plan or a table the executor refuses; the message names a step or a row, never a value."""


@dataclass
class Plan:
    steps: list[dict]


@dataclass
class PlanResult:
    header: list[str]
    rows: list[list]
    chart: dict | None  # {"kind": "bar" | "line" | "pie", "x": column, "y": column, "points": [[x, y], ...]}


def _is_long_whole(s: str) -> bool:
    return _INT.fullmatch(s) is not None and len(s.lstrip("-")) > MAX_DIGITS


def _is_int(s: str) -> bool:
    return _INT.fullmatch(s) is not None and not _is_long_whole(s)


def _is_float(s: str) -> bool:
    return _FLOAT.fullmatch(s) is not None and not _is_long_whole(s) and math.isfinite(float(s))


def _is_date(s: str) -> bool:
    if not _DATE.fullmatch(s):
        return False
    try:
        date.fromisoformat(s)
    except ValueError:
        return False
    return True


_TYPE_TESTS = (("bool", lambda s: s.lower() in _BOOLS), ("int", _is_int), ("float", _is_float), ("date", _is_date))


def _check_cells(cells: int) -> None:
    if cells > MAX_CELLS:
        raise PlanError(f"table: more than {MAX_CELLS} cells")


def _check_table(header: list[str], rows: list[list[str]]) -> None:
    _check_cells(len(header) * max(len(rows), 1))  # before a cell is looked at; a table without rows is one row wide
    if len(set(header)) != len(header):
        raise PlanError("table: two columns have the same name")
    for n, row in enumerate(rows, 1):
        if len(row) != len(header):
            raise PlanError(f"table: row {number(n)} does not have as many cells as the header")


def infer_schema(header: list[str], rows: list[list[str]]) -> TableSchema:
    """A column is the first of bool, int, float, date that fits every non-empty cell, else text."""
    _check_table(header, rows)
    columns = []
    for i, name in enumerate(header):
        cells = [c for c in (row[i].strip() for row in rows) if c]
        kind = next((k for k, test in _TYPE_TESTS if cells and all(test(c) for c in cells)), "text")
        columns.append(Column(name, kind))
    return TableSchema(columns, len(rows))


_SPACES = "[ \u00a0\u202f]"  # digit groups in Russian and European exports
_GROUPED_POINT = re.compile(rf"-?[0-9]{{1,3}}(?:{_SPACES}[0-9]{{3}})+(?:\.[0-9]+)?")
_GROUPED_COMMA = re.compile(rf"-?(?:[0-9]{{1,3}}(?:{_SPACES}[0-9]{{3}})+|[0-9]+)(?:,[0-9]+)?")
_COMMA_EVIDENCE = re.compile(r"-?[0-9]+,(?:[0-9]{1,2}|[0-9]{4,})")  # "1,234" may be thousands, so three digits prove nothing
_POINT_EVIDENCE = re.compile(r"-?[0-9]+\.[0-9]+")
_DMY = re.compile(r"([0-9]{2})\.([0-9]{2})\.([0-9]{4})")


_NUMBER_START = frozenset("-0123456789")  # every pattern above starts with an optional "-" and an ASCII digit


def _unspaced(s: str) -> str:
    """s without the characters of _SPACES; a chain of replace is quicker than re.sub on a table of millions of cells."""
    return s.replace(" ", "").replace("\u00a0", "").replace("\u202f", "")


def guess_decimal(rows: list[list[str]]) -> str:
    """"," when some cell shows a decimal comma and none a decimal point, else ".". A table over MAX_CELLS is refused
    before a cell is read; a decimal point settles it, so the rest of the table is not read."""
    _check_cells(sum(map(len, rows)))
    comma = False
    for row in rows:
        for cell in row:
            s = cell.strip()
            if s[:1] in _NUMBER_START and ("." in s or "," in s):  # only a number with a separator can show which it is
                s = _unspaced(s)
                if _POINT_EVIDENCE.fullmatch(s):
                    return "."
                comma = comma or bool(_COMMA_EVIDENCE.fullmatch(s))
    return "," if comma else "."


def normalize_rows(rows: list[list[str]], decimal: str = ".", columns: set[int] | list[int] | None = None) -> list[list[str]]:
    """Before infer_schema and run_plan: DD.MM.YYYY becomes YYYY-MM-DD, digit groups split by spaces are joined, and
    with decimal="," the comma becomes a point. Percent signs and everything else stay as they are. With columns (a
    collection of indexes) only those columns are normalised and the others come back as they were. A table over
    MAX_CELLS is refused before a cell is read."""
    if decimal not in (".", ","):
        raise ValueError('decimal must be "." or ","')
    _check_cells(sum(map(len, rows)))
    number = _GROUPED_COMMA if decimal == "," else _GROUPED_POINT

    def one(cell: str) -> str:
        s = cell.strip()
        if s[:1] not in _NUMBER_START:  # not a number, not a date
            return cell
        if m := _DMY.fullmatch(s):
            iso = f"{m[3]}-{m[2]}-{m[1]}"
            return iso if _is_date(iso) else cell
        if number.fullmatch(s):
            return _unspaced(s).replace(",", ".")
        return cell

    if columns is None:
        return [[one(cell) for cell in row] for row in rows]
    wanted = sorted(i for i in columns if i >= 0)
    out = [row[:] for row in rows]
    for row in out:
        for i in wanted:
            if i < len(row):  # a short row has no such cell; infer_schema reports it
                row[i] = one(row[i])
    return out


def _looks_like_data(cell: str) -> bool:
    return _NUMBER_LIKE.fullmatch(cell) is not None or any(test(cell) for _, test in _TYPE_TESTS)


def data_like_header(header: list[str]) -> list[str]:
    """Header cells that read as a number, a date or a boolean: the table may have no header, and its first row would
    go to the model as column names. A number counts in any writing, with any number of digits: a 20-digit account
    is not a number for a column, yet no detector knows it and it would go out as it is."""
    return [name for name in header if _looks_like_data(name.strip())]


def _sample(kind: str, rng: random.Random) -> str:
    if kind == "int":
        return str(rng.randrange(100_000, 1_000_000))
    if kind == "float":
        return f"{rng.randrange(100_000, 10_000_000) / 100:.2f}"
    if kind == "date":
        return (date(2001, 1, 1) + timedelta(days=rng.randrange(3650))).isoformat()
    if kind == "bool":
        return rng.choice(_BOOLS)
    return "sample-" + "".join(rng.choices(string.ascii_lowercase + string.digits, k=6))


def synthetic_rows(schema: TableSchema, n: int = 3, seed: int = 0) -> list[list[str]]:
    """Placeholders made from the column types and the seed alone: nothing of the real rows can reach them."""
    rng = random.Random(seed)
    return [[_sample(c.type, rng) for c in schema.columns] for _ in range(n)]


def _is_number(v) -> bool:
    return type(v) is int or (type(v) is float and math.isfinite(v))


def _is_text(v) -> bool:
    """A string that a file can hold: a lone surrogate (a JSON "\\ud800") cannot be written as UTF-8."""
    if type(v) is not str:
        return False
    try:
        v.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


_VALUE_FITS = {
    "int": _is_number,
    "float": _is_number,
    "date": lambda v: type(v) is str and _is_date(v),
    "bool": lambda v: type(v) is bool,
    "text": _is_text,
}


def _bad(n: int, why: str) -> PlanError:
    """The error of step n. why is fixed words: tests/test_error_texts.py reads every call of _bad."""
    return PlanError(f"step {number(n)}: {why}")


def _kind(n: int, name, cols: dict[str, str], allowed: tuple[str, ...] = COLUMN_TYPES) -> str:
    """The type of a column that exists at this point and may be used here."""
    if type(name) is not str or name not in cols:
        raise _bad(n, "unknown column")
    if cols[name] not in allowed:
        raise _bad(n, "column type does not fit this operation")
    return cols[name]


def _columns(n: int, names, cols: dict[str, str], minimum: int = 1) -> list[str]:
    if type(names) is not list or not minimum <= len(names) <= len(cols):
        raise _bad(n, "needs a list of distinct columns")
    for name in names:
        _kind(n, name, cols)
    if len(set(names)) != len(names):
        raise _bad(n, "needs a list of distinct columns")
    return names


def _new_name(n: int, name, taken: dict[str, str]) -> str:
    if type(name) is not str or not _NAME.fullmatch(name) or name in taken:
        raise _bad(
            n,
            f"a new column needs an unused name of 1 to {MAX_NAME} letters, digits, spaces or _ - . % ( ), "
            "starting with a letter or digit",
        )
    return name


def _filter(n: int, step: dict, cols: dict[str, str]) -> dict[str, str]:
    kind = _kind(n, step["column"], cols)
    cmp = step["cmp"]
    if type(cmp) is not str or cmp not in _CMPS:
        raise _bad(n, "unknown comparison")
    if cmp == "contains" and kind != "text" or cmp in ("<", "<=", ">", ">=") and kind not in _ORDERED:
        raise _bad(n, "comparison does not fit the column type")
    if not _VALUE_FITS[kind](step["value"]):
        raise _bad(n, "value does not fit the column type")
    return cols


def _derive(n: int, step: dict, cols: dict[str, str]) -> dict[str, str]:
    _kind(n, step["left"], cols, _NUMERIC)
    right = step["right"]
    if type(right) is str:
        _kind(n, right, cols, _NUMERIC)
    elif not _is_number(right):
        raise _bad(n, "right must be a numeric column or a number")
    operator = step["operator"]
    if type(operator) is not str or operator not in _OPERATORS:
        raise _bad(n, "unknown operator")
    # int or float: later steps treat both alike
    return {**cols, _new_name(n, step["name"], cols): "float"}


def _group(n: int, step: dict, cols: dict[str, str]) -> dict[str, str]:
    by = _columns(n, step["by"], cols, minimum=0)
    aggregates = step["aggregates"]
    if type(aggregates) is not dict or not 1 <= len(aggregates) <= MAX_AGGREGATES:
        raise _bad(n, f"needs 1 to {MAX_AGGREGATES} aggregates")
    out = {name: cols[name] for name in by}
    for name, spec in aggregates.items():
        _new_name(n, name, out)
        if type(spec) is not list or len(spec) != 2 or type(spec[0]) is not str or spec[0] not in _AGGREGATES:
            raise _bad(n, "an aggregate is [function, column]")
        func, column = spec
        kind = _kind(n, column, cols, _AGGREGATES[func])
        out[name] = {"count": "int", "mean": "float"}.get(func, kind)
    return out


def _sort(n: int, step: dict, cols: dict[str, str]) -> dict[str, str]:
    _columns(n, step["by"], cols)
    if type(step["desc"]) is not bool:
        raise _bad(n, "desc must be true or false")
    return cols


def _limit(n: int, step: dict, cols: dict[str, str]) -> dict[str, str]:
    if type(step["n"]) is not int or not 1 <= step["n"] <= MAX_LIMIT:
        raise _bad(n, f"n must be a whole number from 1 to {MAX_LIMIT}")
    return cols


def _select(n: int, step: dict, cols: dict[str, str]) -> dict[str, str]:
    return {name: cols[name] for name in _columns(n, step["columns"], cols)}


def _chart(n: int, step: dict, cols: dict[str, str]) -> dict[str, str]:
    if type(step["kind"]) is not str or step["kind"] not in _CHARTS:
        raise _bad(n, "unknown chart kind")
    _kind(n, step["x"], cols)
    _kind(n, step["y"], cols, _NUMERIC)
    return cols


# the whole grammar: operation -> (its keys besides "op", its check)
_OPS = {
    "filter": (("column", "cmp", "value"), _filter),
    "derive": (("name", "left", "operator", "right"), _derive),
    "group": (("by", "aggregates"), _group),
    "sort": (("by", "desc"), _sort),
    "limit": (("n",), _limit),
    "select": (("columns",), _select),
    "chart": (("kind", "x", "y"), _chart),
}


def _check(steps, columns: dict[str, str]) -> None:
    """Walk the steps over the column types the way the executor will; the first step that does not fit raises."""
    if type(steps) is not list or not 1 <= len(steps) <= MAX_STEPS:
        raise PlanError(f"plan: needs 1 to {MAX_STEPS} steps")
    cols = dict(columns)
    made = 0
    for n, step in enumerate(steps, 1):
        op = step.get("op") if type(step) is dict else None
        if type(op) is not str or op not in _OPS:
            raise _bad(n, "unknown operation")
        keys, check = _OPS[op]
        if set(step) != {"op", *keys}:
            raise _bad(n, "wrong keys for this operation")
        if op == "chart" and n != len(steps):
            raise _bad(n, "a chart is the last step, once")
        cols = check(n, step, cols)
        if op == "derive":
            made += 1
        elif op == "group":
            made += len(step["aggregates"])
        if made > MAX_NEW_COLUMNS:
            raise _bad(n, f"a plan makes at most {MAX_NEW_COLUMNS} new columns, derive steps and aggregates together")


def _object(pairs: list[tuple[str, object]]) -> dict:
    out = dict(pairs)
    if len(out) != len(pairs):
        raise ValueError("repeated key")
    return out


def _finite(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):
        raise ValueError("number out of range")
    return value


def _constant(name: str) -> None:
    raise ValueError("NaN and Infinity are not accepted")


def _load(text: str) -> dict:
    """The answer as a dict with exactly the keys version and steps: one JSON object, bare or in a single code block."""
    if len(text) > MAX_PLAN_CHARS:
        raise PlanError("plan: the answer is too long")
    pieces = text.split("```")  # no regex: a hostile answer must not make the matcher backtrack
    if len(pieces) not in (1, 3):
        raise PlanError("plan: needs one complete code block or none")
    body = pieces[1].lstrip(_FENCE_TAG) if len(pieces) == 3 else text
    try:
        data = json.loads(body, object_pairs_hook=_object, parse_float=_finite, parse_constant=_constant)
    except (ValueError, RecursionError):
        raise PlanError("plan: not valid JSON") from None
    if type(data) is not dict or set(data) != {"version", "steps"}:
        raise PlanError("plan: needs exactly the keys version and steps")
    if type(data["version"]) is not int or data["version"] != 1:
        raise PlanError("plan: version must be 1")
    return data


def parse_plan(text: str, schema: TableSchema) -> Plan:
    """The answer is data: one JSON object, bare or in a single code block, that fits the grammar and the schema."""
    data = _load(text)
    _check(data["steps"], {c.name: c.type for c in schema.columns})
    return Plan(steps=data["steps"])


def plan_columns(text: str, header: list[str]) -> set[int] | None:
    """The columns whose cells a plan can read or let through to its result, as indexes into header; None for all of
    them. Only these need normalising before the plan runs (normalize_rows columns=). group and select drop every column
    they do not name, so these are the columns named anywhere in the steps: a name in a value counts too, which can only
    make the set larger. A plan that drops nothing, and a text that is no plan (parse_plan says what is wrong), need them all."""
    try:
        steps = _load(text)["steps"]
    except PlanError:
        return None
    if type(steps) is not list or not all(type(step) is dict for step in steps):
        return None
    if not any(step.get("op") in ("group", "select") for step in steps):
        return None
    named, pending = set(), list(steps)
    while pending:  # a value can be nested as deep as the parser goes, so no recursion
        item = pending.pop()
        if type(item) is str:
            named.add(item)
        elif type(item) is list:
            pending += item
        elif type(item) is dict:
            pending += item.keys()
            pending += item.values()
    return {i for i, name in enumerate(header) if name in named}


_INTRO = (
    "You cannot see the table. You get the task, the columns with their types and a few made-up rows. "
    "Reply with a plan of operations: it will be run on the real table on my computer, so write no code "
    "and do not guess at values."
)

_EXAMPLE = {
    "version": 1,
    "steps": [
        {"op": "derive", "name": "margin", "left": "revenue", "operator": "-", "right": "cost"},
        {"op": "group", "by": ["client"], "aggregates": {"total_margin": ["sum", "margin"]}},
        {"op": "sort", "by": ["total_margin"], "desc": True},
        {"op": "limit", "n": 10},
        {"op": "chart", "kind": "bar", "x": "client", "y": "total_margin"},
    ],
}

_GRAMMAR = string.Template(
    """\
A plan is one JSON object {"version": 1, "steps": [...]} with 1 to $steps steps that run in order. Every key shown is required and no other key is allowed. C is a column name. The steps:
{"op": "filter", "column": C, "cmp": "==" | "!=" | ">" | ">=" | "<" | "<=" | "contains", "value": V}
{"op": "derive", "name": NEW, "left": C, "operator": "+" | "-" | "*" | "/", "right": C or a number}
{"op": "group", "by": [C, ...], "aggregates": {OUT: ["sum" | "mean" | "count" | "min" | "max", C]}}
{"op": "sort", "by": [C, ...], "desc": true or false}
{"op": "limit", "n": a whole number from 1 to $limit}
{"op": "select", "columns": [C, ...]}
{"op": "chart", "kind": "bar" | "line" | "pie", "x": C, "y": C}

Rules:
- C must exist at that point: a column of the table, or one made by an earlier derive or group step. After group only its by columns and aggregates remain, after select only the selected columns.
- V has the type of the column: a number for int and float, "YYYY-MM-DD" for date, true or false for bool, a string for text. Use > >= < <= on int, float and date columns only and contains on text only (case-sensitive). An empty cell matches no filter.
- derive needs int or float columns or numbers; dividing by zero gives an empty value. sum and mean need int or float, min and max need int, float or date, count works on any column. Aggregates skip empty cells.
- NEW and OUT are new names of 1 to $name characters: letters, digits, spaces and _ - . % ( ), starting with a letter or digit, and not a column that exists at that point.
- Size: a plan makes at most $new new columns (every derive step and every aggregate counts as one), and after every step the table has at most $cells cells (rows times columns). A derive or group step that would go past that is refused, so filter or limit before it when the task allows.
- group needs 1 to $aggregates aggregates; by may be [] for one row of totals. sort puts empty cells last.
- chart is the last step and used at most once; y must be int or float.

Example, for a table with the columns client (text), revenue (float) and cost (float) and the task "top 10 clients by margin":
$example

Answer with the plan only: one JSON object in a single code block. If the task cannot be done with these steps, answer with one sentence saying why and no plan."""
).substitute(
    steps=MAX_STEPS,
    limit=MAX_LIMIT,
    name=MAX_NAME,
    aggregates=MAX_AGGREGATES,
    new=MAX_NEW_COLUMNS,
    cells=MAX_CELLS,
    example=json.dumps(_EXAMPLE),
)


def plan_prompt(task: str, schema: TableSchema, examples: int = 3, *, header_confirmed: bool = False) -> str:
    """What goes to the cloud model at level 4: the task, names and types of the columns, made-up rows and the grammar."""
    if not header_confirmed and data_like_header([c.name for c in schema.columns]):
        raise PlanError("the header looks like a data row: check that the table has a header, then confirm it")
    columns = "\n".join(f"- {json.dumps(c.name, ensure_ascii=False)} ({c.type})" for c in schema.columns)
    parts = [_INTRO, f"Task:\n{task}", f"Columns with their types:\n{columns}"]
    if examples > 0:
        out = io.StringIO()
        writer = csv.writer(out, lineterminator="\n")
        writer.writerow(c.name for c in schema.columns)
        writer.writerows(synthetic_rows(schema, examples))
        parts.append(f"Made-up example rows, built from the column types alone (not real data):\n{out.getvalue().rstrip()}")
    return "\n\n".join([*parts, _GRAMMAR])


_COMPARE = {"==": eq, "!=": ne, ">": gt, ">=": ge, "<": lt, "<=": le, "contains": contains}
_ARITHMETIC = {"+": add, "-": sub, "*": mul, "/": truediv}
_MAX_INT_BITS = 1024  # as far as a float goes


def _cell(kind: str, cell: str):
    """A cell as a Python value of its column type; an empty cell is None. Dates stay YYYY-MM-DD strings."""
    s = cell.strip()
    if not s:
        return None
    if kind == "int":
        return int(s)
    if kind == "float":
        return float(s)
    if kind == "bool":
        return s.lower() == "true"
    return s if kind == "date" else cell


def _held(value):
    """A computed number if a table can hold it: an int within the float range, a finite float; else None.
    Without the bound a plan of squarings doubles the digits of every cell with each step."""
    if type(value) is int:
        return value if value.bit_length() <= _MAX_INT_BITS else None
    return value if math.isfinite(value) else None


def _arith(symbol: str, a, b):
    """None for an empty operand, a division by zero or a result a table cannot hold."""
    if a is None or b is None:
        return None
    try:
        return _held(_ARITHMETIC[symbol](a, b))
    except (ZeroDivisionError, OverflowError):
        return None


def _aggregate(func: str, values: list):
    """Empty cells are skipped; with nothing left the result is None, a count is 0. Int sums stay exact."""
    present = [v for v in values if v is not None]
    if func == "count":
        return len(present)
    if not present:
        return None
    if func == "min":
        return min(present)
    if func == "max":
        return max(present)
    try:
        total = sum(present)  # exact for ints, compensated for floats since Python 3.12
        return _held(total if func == "sum" else total / len(present))
    except OverflowError:
        return None


def _within_budget(n: int, rows: int, columns: int) -> None:
    """Before a step builds more columns: the table it makes stays within MAX_CELLS. The message names the step, no value."""
    if rows * columns > MAX_CELLS:
        raise _bad(n, f"the table would have more than {MAX_CELLS} cells")


def _group_rows(n: int, names: list[str], table: list[list], step: dict) -> tuple[list[str], list[list]]:
    by = [names.index(c) for c in step["by"]]
    width = len(by) + len(step["aggregates"])
    groups: dict[tuple, list[list]] = {}
    for row in table:
        key = tuple(row[i] for i in by)
        members = groups.get(key)
        if members is None:  # a new group: the table must still fit with it, before the next row is read
            _within_budget(n, len(groups) + 1, width)
            members = groups[key] = []
        members.append(row)
    if not by:
        groups.setdefault((), [])  # by [] is one row of totals, also when no row is left
    aggregates = [(out, func, names.index(column)) for out, (func, column) in step["aggregates"].items()]
    rows = [[*key, *(_aggregate(func, [r[i] for r in members]) for _, func, i in aggregates)] for key, members in groups.items()]
    return [*step["by"], *(out for out, _, _ in aggregates)], rows


def _sort_key(i: int, desc: bool):
    """Empty cells go last in both directions: the flag decides before an empty cell meets a value."""

    def key(row: list):
        empty = row[i] is None
        return (not empty if desc else empty), row[i]

    return key


def _sort_rows(names: list[str], table: list[list], step: dict) -> None:
    """One stable pass per column, the last one first."""
    for column in reversed(step["by"]):
        table.sort(key=_sort_key(names.index(column), step["desc"]), reverse=step["desc"])


def run_plan(plan: Plan, header: list[str], rows: list[list[str]]) -> PlanResult:
    """Run the steps on the real rows. The plan is checked again against the types of these rows: a Plan is only a dataclass."""
    schema = infer_schema(header, rows)
    _check(plan.steps, {c.name: c.type for c in schema.columns})
    names = list(header)
    table = [[_cell(c.type, cell) for c, cell in zip(schema.columns, row)] for row in rows]
    chart = None
    for n, step in enumerate(plan.steps, 1):
        op = step["op"]
        if op == "filter":
            i, test, value = names.index(step["column"]), _COMPARE[step["cmp"]], step["value"]
            table = [row for row in table if row[i] is not None and test(row[i], value)]
        elif op == "derive":
            _within_budget(n, len(table), len(names) + 1)
            left, right = names.index(step["left"]), step["right"]
            j = names.index(right) if type(right) is str else None
            for row in table:
                row.append(_arith(step["operator"], row[left], right if j is None else row[j]))
            names.append(step["name"])
        elif op == "group":
            names, table = _group_rows(n, names, table, step)
        elif op == "sort":
            _sort_rows(names, table, step)
        elif op == "limit":
            table = table[: step["n"]]
        elif op == "select":
            picked = [names.index(c) for c in step["columns"]]
            table = [[row[i] for i in picked] for row in table]
            names = list(step["columns"])
        else:
            x, y = names.index(step["x"]), names.index(step["y"])
            points = [[row[x], row[y]] for row in table if row[x] is not None and row[y] is not None]
            chart = {"kind": step["kind"], "x": step["x"], "y": step["y"], "points": points}
    return PlanResult(names, table, chart)
