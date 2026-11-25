# Tables at level 4

Level 4 is for tables. The model never gets your rows. It gets the task and the table schema (column names and types) with made-up rows, and it answers with a plan of operations. boxed runs the plan on your real table, on your computer.

Use it when the table holds data you do not want to send at all, for example sales, payroll or client lists, and the task is a calculation: filter, sum, group, sort, rank.

## How it works

1. `boxed plan prompt` reads your table and prints a prompt. The prompt holds the masked task, the column names and types, three made-up rows and the plan grammar.
2. You paste the prompt into an AI chat and save the model's answer to a file.
3. `boxed plan run` checks the answer against the grammar and your table, and runs it locally.

boxed does not send the prompt. `boxed ask` refuses level 4 (see [api.md](api.md)), so you paste the prompt into the chat yourself. The model's answer is data, never code. boxed reads it as strict JSON and runs only the operations in the grammar.

## Build the prompt

```text
$ boxed plan prompt --scope top3 --task "top 3 clients by margin" sales.csv
You cannot see the table. You get the task, the columns with their types and a few made-up rows. Reply with a plan of operations: it will be run on the real table on my computer, so write no code and do not guess at values.

Task:
top 3 clients by margin

Columns with their types:
- "client" (text)
- "region" (text)
- "revenue" (float)
- "cost" (float)
- "order_date" (date)

Made-up example rows, built from the column types alone (not real data):
client,region,revenue,cost,order_date
sample-41pjso,sample-2krv6s,48284.54,24445.45,2009-06-23
sample-d29tzv,sample-fdc4lu,60356.33,73841.94,2004-07-19
sample-v68r5j,sample-2tazo3,1191.73,83808.62,2010-04-15

A plan is one JSON object {"version": 1, "steps": [...]} with 1 to 50 steps that run in order. ...
...
Answer with the plan only: one JSON object in a single code block. If the task cannot be done with these steps, answer with one sentence saying why and no plan.
scope: top3; decimal: .
```

The prompt goes to standard output. The line `scope: top3; decimal: .` goes to standard error: it names the scope and the decimal mark boxed found. `sales.csv` is the table.

**What is in the prompt:** the task, the column names, the column types, three made-up rows and the grammar. **What is not:** any of your rows, any cell value, the number of rows. The made-up rows come from the column types and a fixed seed, so the same column types give the same rows every time. Nothing of your data can reach them.

**The task and the column names are masked.** boxed masks them with the detectors, at the `level` of your `boxed.toml` (2 if unset), and with your dictionary (the dictionary applies from level 2). A client named in the task becomes a placeholder:

```text
$ boxed plan prompt --scope acme --task "margin per order of Acme GmbH" sales.csv
...
Task:
margin per order of [CLIENT_1]
```

That works for a client in your dictionary (see [configuration.md](configuration.md)). A name that no detector and no dictionary knows goes out as you wrote it, in the task and in the column names. Check the prompt before you paste it.

Options of `plan prompt`:

| Option | Meaning |
|---|---|
| `--task TEXT` | What you want, in plain words. Required. |
| `--scope NAME` | The set of placeholders. The default is `plan-<UTC date and time>`. You need it to run the plan. |
| `--decimal auto\|.\|,` | The decimal mark of the table. `auto` guesses (see "Number formats"). |
| `--header-ok` | The first row is a header, although it looks like data. |

**The header check.** If any cell of the first row looks like data (a number, a date, true or false), the table may have no header, and the first row would go to the model as column names. boxed refuses:

```text
boxed: error: the header looks like a data row: check that the table has a header, then confirm it
```

Look at the table. If the first row really is a header, add `--header-ok`. If there is no header, add one.

## Ask a model

Paste the prompt into the chat of your choice. The prompt tells the model to answer with the plan only, in one JSON object, in one code block. Save the answer to a file, for example `answer.txt`:

````text
```json
{"version": 1, "steps": [
  {"op": "derive", "name": "margin", "left": "revenue", "operator": "-", "right": "cost"},
  {"op": "group", "by": ["client"], "aggregates": {"total_margin": ["sum", "margin"]}},
  {"op": "sort", "by": ["total_margin"], "desc": true},
  {"op": "limit", "n": 3},
  {"op": "chart", "kind": "bar", "x": "client", "y": "total_margin"}
]}
```
````

boxed accepts the JSON bare, or inside one code block. Words around a code block are ignored. A bare answer must be only the JSON. boxed refuses two code blocks, because it cannot tell which one is the plan.

## Run the plan

```text
$ boxed plan run --scope top3 answer.txt sales.csv
client,total_margin
Initech,8000.0
Acme GmbH,6500.5
Umbrella,3999.5
```

The arguments are the answer file and the table. `--scope` must be the scope of the prompt: boxed restores the placeholders of the masked task in the plan (a client name the model repeated as `[CLIENT_1]`) before it runs it. If the plan holds a placeholder boxed does not know, it does not run:

```text
plan not run, check these placeholders: [EMAIL_9]
```

The exit code is 3. Options of `plan run`:

| Option | Meaning |
|---|---|
| `--out FILE` | Write the result table here instead of standard output. |
| `--chart FILE` | Write the chart (JSON) here, if the plan has a chart step. Without this option, a chart step is checked but its data is not saved. |
| `--replace` | Replace a `--out` file that is already there, or a `--chart` file that is not a chart. |
| `--decimal auto\|.\|,` | As for the prompt. |

`--out` never overwrites an existing file without `--replace`. A `--chart` file that boxed wrote earlier is replaced without it; any other existing file is not. Both refuse a link and a path inside the boxed folder.

The result keeps the delimiter of your table (`,` `;` tab or `\|`). The chart is a JSON spec with the points. boxed draws nothing:

```text
{"kind": "bar", "x": "client", "y": "total_margin", "points": [["Initech", 8000.0], ["Acme GmbH", 6500.5], ["Umbrella", 3999.5]]}
```

The result writes numbers with a decimal point, floats the way Python prints them (`8000.0`), booleans as `True` and `False`, and an empty value as an empty cell.

## The plan

A plan is one JSON object with exactly two keys: `"version"`, which must be `1`, and `"steps"`, a list of 1 to 50 steps. Steps run in order. Every key in a step is required, and no other key is allowed. A repeated key, `NaN` and `Infinity` are refused.

| Step | Keys | What it does |
|---|---|---|
| `filter` | `column`, `cmp`, `value` | Keeps the rows where the comparison holds. `cmp` is `==`, `!=`, `>`, `>=`, `<`, `<=` or `contains`. |
| `derive` | `name`, `left`, `operator`, `right` | Adds a column: `left` (a number column) `+ - * /` `right` (a number column, or a number). Dividing by zero gives an empty value. |
| `group` | `by`, `aggregates` | One row for each distinct combination of the `by` columns. `aggregates` maps a new name to `[function, column]`. The functions are `sum`, `mean`, `count`, `min` and `max`. `by` may be `[]` for one row of totals. |
| `sort` | `by`, `desc` | Sorts by the columns, in the order given. `desc` is `true` or `false` and applies to all of them. Empty cells go last. |
| `limit` | `n` | Keeps the first `n` rows, 1 to 10000. |
| `select` | `columns` | Keeps these columns, in this order. |
| `chart` | `kind`, `x`, `y` | The last step, once. `kind` is `bar`, `line` or `pie`. `y` must be a number column. |

Rules that boxed checks against your table before it runs anything:

- A column must exist at that point: a column of the table, or one made by an earlier `derive` or `group`. After `group` only its `by` columns and its aggregates remain. After `select` only the selected columns remain.
- `value` has the type of the column: a number for `int` and `float`, `"YYYY-MM-DD"` for `date`, `true` or `false` for `bool`, a string for `text`. `>`, `>=`, `<` and `<=` work on number and date columns. `contains` works on text and is case-sensitive. An empty cell matches no filter.
- `sum` and `mean` need number columns. `min` and `max` need number or date columns. `count` works on any column, and it skips empty cells like all aggregates do.
- New names have 1 to 64 letters, digits, spaces and `_ - . % ( )`, and start with a letter or digit. `derive` refuses a name that is already a column. The prompt asks the model for names that are not columns at that point.
- `group` takes 1 to 20 aggregates. Groups come out in the order their first row appears. Add a `sort` to order them.

## Column types and number formats

boxed gives each column the first of these types that fits every non-empty cell:

| Type | Fits |
|---|---|
| `bool` | `true` or `false`, in any case |
| `int` | A whole number without a plus sign, leading zeros, exponent or decimal mark, up to 15 digits. `-5` is an int. |
| `float` | A number with an optional decimal point, such as `10.50` or `.5`. |
| `date` | `YYYY-MM-DD`, and a real date. |
| `text` | Everything else. |

Two things follow. A column with whole numbers and decimals is `float`. A column with `12%`, `$5`, `007`, `+5`, `1e3` or a 16-digit number is `text`: percent signs, currency signs, leading zeros and long identifiers (a card or an account number) are not numbers for boxed. A text column cannot be summed. Clean such a column in the table first. Empty cells are allowed.

Before it looks at types, boxed normalises the table:

- `DD.MM.YYYY` becomes `YYYY-MM-DD`.
- Digit groups separated by spaces (also non-breaking spaces) are joined: `12 400.50` becomes `12400.50`.
- With the decimal mark `,`, the comma becomes a point as well: `12 400,50` becomes `12400.50`.

`--decimal` says which mark the table uses. `auto` (the default) picks `,` when some cell shows a decimal comma (`12,50`, with one or two digits after it, or four or more) and no cell shows a decimal point, and `.` otherwise. A comma as a thousands mark (`1,234.50`) is not read, and `1,234` alone proves nothing, so remove thousands commas first. The date format does not depend on `--decimal`.

```text
$ boxed plan run --scope t3 answer-ventes.txt ventes.csv
client;total_margin;orders;first_order
Acme GmbH;6500.5;2;2026-09-03
Initech;5350.75;1;2026-09-11
Globex;2499.75;1;2026-09-05
```

This table (`ventes.csv`) uses `;`, spaces in numbers, decimal commas and `DD.MM.YYYY` dates. `auto` found the decimal comma. Forcing the wrong mark turns the number columns into text, and the plan is refused:

```text
$ boxed plan run --scope t3 --decimal . answer-ventes.txt ventes.csv
boxed: error: step 1: column type does not fit this operation
```

## Budgets

| Limit | Value |
|---|---|
| Steps in a plan | 50 |
| New columns in a whole plan (every `derive` and every aggregate) | 50 |
| Aggregates in one `group` | 20 |
| `limit` | `n` from 1 to 10000 |
| Length of a new name | 64 characters |
| Length of the model's answer | 100,000 characters |
| Cells (rows times columns) | 5,000,000, in the table and after every step |

boxed refuses a table over the limit before it types the table or runs a step. It checks the size again after each step. One plan cannot use unbounded time or memory:

```text
boxed: error: table: more than 5000000 cells
boxed: error: step 3: the table would have more than 5000000 cells
```

The prompt tells the model all of these limits except the length of its answer, so it can filter or limit before an expensive step.

## What is refused

Everything outside the grammar. The messages name a step, never a value:

| Message | Cause |
|---|---|
| `plan: not valid JSON` | The answer is not valid JSON. A sentence without a plan ends here too. |
| `plan: needs one complete code block or none` | Two code blocks, or one that is not closed. |
| `plan: needs exactly the keys version and steps` | The JSON is not an object, or it has a missing or extra key at the top. |
| `plan: needs 1 to 50 steps` | No steps, or too many. |
| `step 1: unknown operation` | An operation outside the seven, such as `sql`. |
| `step 1: wrong keys for this operation` | A key is missing or extra. |
| `step 1: unknown column` | The column does not exist at that point. |
| `step 1: column type does not fit this operation` | For example, `sum` on a text column. |
| `step 1: value does not fit the column type` | For example, a string for a number column. |
| `step 1: n must be a whole number from 1 to 10000` | A `limit` over 10000. |
| `step 5: a chart is the last step, once` | A chart that is not last. |

The exit code is 2 for each. boxed checks every step against the column types before it runs the first one, and it writes no result when a step fails.

## The journal

`plan prompt` writes a record (`manual`, `prepared`, level 4) with the coverage `level 4: task and schema only` and the number of placeholders in the task and column names. `plan run` writes a record (`received`, level 4) with the coverage `level 4 plan run, N rows` and the hash of the answer. It does so before it writes any result. Neither holds a value.

## Limits

- **Masking does not stop inference from context.** Level 4 hides your rows. The task and the column names still describe your business, and a model can guess a lot from them. Choose neutral column names if they are sensitive. Names and companies in the task are found only with a name model or your dictionary (see [install.md](install.md)).
- **The model cannot see your values.** A filter on a text column must match the cell exactly, so give the exact spelling in the task.
- **Seven operations only.** No joins, no second table, no text functions, no date arithmetic, no formulas. A task outside them gets no plan.
- **CSV and delimited text only.** The table must be UTF-8 (`,` `;` tab or `|`). Export an XLSX to CSV first.
- **boxed does not check the policy for a plan.** `boxed plan prompt` builds the prompt from the schema and does not consult your company rules. Where you may paste even a schema is your decision (see [policy.md](policy.md)).
- **The result is only as good as the model's plan.** boxed runs it exactly. Read the plan before you trust the numbers.
- **The journal proves what boxed recorded.** It does not prove that nothing was sent around boxed.
