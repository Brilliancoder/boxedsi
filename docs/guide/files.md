# Files

`boxed mask-file` builds a clean, masked copy of a CSV, XLSX, DOCX or PDF file. You upload the copy to an AI service by hand. `boxed restore-file` puts the originals back into the file the model returns.

boxed never sends your source file and never changes it. It builds a new file from what it checked and lists what it left out. You decide from that list whether the copy is safe to send.

| Format | Mask | Restore | Needs the `formats` extra | Output of mask |
|---|---|---|---|---|
| CSV (`.csv`) | yes | yes | no | a CSV |
| Excel (`.xlsx`) | yes | yes | yes | an XLSX |
| Word (`.docx`) | yes | yes | yes | a DOCX |
| PDF (`.pdf`) | text layer only | the `.txt` made from it | yes, to mask | a `.txt` file |

Without the `formats` extra, an XLSX, DOCX or PDF stops with `this file type needs the formats extra`. See [install.md](install.md). Other file types stop with `unsupported file type; supported: .csv, .docx, .pdf, .xlsx` (`restore-file`: `.csv, .docx, .txt, .xlsx`). A CSV or a `.txt` must be UTF-8. A CSV in UTF-16 or UTF-32 is refused.

## Mask a file

```text
$ boxed mask-file --scope deal-7 clients.xlsx clients.masked.xlsx
xlsx: clients.xlsx -> clients.masked.xlsx
checked: sheet Clients
markers: EMAIL 3, PHONE 3
complete: yes
scope: deal-7
```

The arguments are the source and the new file. The new file is the copy to upload. Options:

- `--scope NAME`: the set of placeholders to use. Without it boxed makes `file-<UTC date and time>`. The report prints the scope on standard error. Use one scope for a file and its answer, and for related files, so equal values get equal placeholders.
- `--level N`: 0 to 3. The default is `level` in `boxed.toml` (2 if unset). Level 4 is refused: it is the plan route for tables (see [tables.md](tables.md)).
- `--replace`: replace a file that is already there (see "Safety rules").
- `--delimiter comma|semicolon|tab|pipe`: the delimiter of a CSV file. Without it boxed reads the delimiter from the header and the data rows together: the header must make two cells or more with it, and every row must fit (a row may leave out empty fields at its end). When more than one delimiter fits, or none, boxed refuses rather than guess, because a wrong guess makes the header one cell and copies the values under `password` as they are: `the delimiter of this csv file cannot be told for sure: name it (boxed mask-file --delimiter comma, semicolon, tab or pipe)`. `restore-file` takes the same option.

The report has these lines:

- `<format>: <source> -> <output>`: the file names, masked.
- `checked:` what boxed read.
- `left out:` what boxed did not copy. This line is missing when nothing was left out.
- `markers:` how many placeholders of each kind it placed.
- `complete:` `yes`, or `no - check what was left out before you send it`.

**`complete: no` means something that could hold data was left out.** The copy lacks a part the original had. boxed leaves such a part out instead of guessing at it, so it does not go to the model, and the model does not see it either. Read the `left out:` line. If a missing part matters for your task, deal with it yourself, for example by pasting a comment's text into your prompt through `boxed mask`.

```text
$ boxed mask-file --scope deal-9 clients-notes.xlsx clients-notes.masked.xlsx
xlsx: clients-notes.xlsx -> clients-notes.masked.xlsx
checked: sheet Clients
left out: hidden sheet Notes; hidden columns; comments
markers: EMAIL 3, PHONE 3
complete: no - check what was left out before you send it
scope: deal-9
```

A `left out:` line can also list notes that do not make a copy incomplete: `character formatting`, `document properties`, `document thumbnail` and `formulas (cached values kept)`. Almost every Office file has an author and formatting, and the copy carries none of them. The `complete:` line decides.

## What is checked, and what is left out

The copy holds only what boxed read. What boxed did not read is not in the copy. The report names most of it.

| Format | Checked | Named as left out (makes the copy incomplete) |
|---|---|---|
| CSV | Every cell. The delimiter (`,` `;` tab or `\|`), line ends, byte order mark and final newline stay. Quoting becomes minimal. | Nothing. |
| XLSX | Values of the visible sheets and the sheet names. Text is masked. Numbers, dates and times are masked from level 3 on, below that only whole numbers (see below). | Hidden and very hidden sheets, hidden rows and columns, comments, images and charts, defined names, data validation, external links, pivot tables, hyperlink targets (the link text stays), print headers and footers, formulas without a cached result, and a sheet name that had to change to fit Excel (forbidden characters, over 31 characters, a duplicate). |
| DOCX | Body paragraphs, tables, and the headers and footers of the first section. | Comments, tracked changes, hidden text, images and embedded objects, footnotes, endnotes, content controls, headers and footers of later sections, text in fields, smart tags and equations, hyperlink targets. |
| PDF | The text layer of every page. | Images, annotations, attachments and document properties. A PDF is never complete. |

Details worth knowing:

- **A column whose header names a secret is masked whole.** In a CSV (any delimiter, tab included) the first row that holds anything is the header. On every sheet of an XLSX the headers are the first row that holds anything, the first row that holds a visible value (a hidden row above the header does not hide it), and the header row of every table the sheet declares (Insert > Table), which counts down to the end of that table. When a header cell names a secret (`password`, `Password`, `pwd`, `token`, `secret`, `API key`, `access key`, `DB_PASSWORD`, `Пароль`, the same names the text detector reads in a table), every value below it becomes one `[SECRET_n]`, however plain it looks (`summer2024`). An empty cell stays empty. A number keeps its type through `restore-file`, as other number cells do. Headers such as `key` or `db_password` (lower case with an underscore) are not read as secret names: such values are only masked when they look like a secret.
- **XLSX is rebuilt from values.** Formatting, column widths and merged cells are not kept. A formula is replaced by the value Excel last calculated. A workbook that a script wrote has no calculated values, so its formulas turn into empty cells and the report says `formulas without cached values (left empty): 2`.
- **Which cells go through the detectors depends on the level.** At levels 0 to 2, text cells and whole numbers do. A card number stored as a whole number in a cell is masked as `[CARD_1]`, and the cell becomes text. A decimal number, a date, a time and a true/false value are copied as they are. From level 3 on, every number, date and time cell goes through the detectors, read the way Excel shows it under the number format of the cell (`15%`, `1,234.50 EUR`, `21.10.2026`). boxed checks the stored value too, so digits or a day that the format hides (`0`, `mmm`) are masked as well. A cell that boxed changes becomes text with a placeholder: `[PERCENT_1]`, `[MONEY_2]`, `[DATE_3]`, `[NUMBER_4]`. A lone digit stays, as in text, unless its format makes it an amount or a percentage (`$5`, `5%`). True/false values stay at every level.
- **A placeholder for a number or date cell stands for the text Excel showed.** Cells that show the same text (`42.2%`, `1,234,567.89 EUR`, `21.10.2026`) share a placeholder, and in prose it comes back as that text. `restore-file` puts the stored value back (`0.4217`, a date, a time, a duration) only into the cell where the masked copy had the placeholder: the same sheet, the same address, and nothing else in the cell. A placeholder anywhere else (moved, copied or written by the model), and a text cell that shows the same digits as a number cell, comes back as the text that was shown. Number formats are not kept: a restored date shows as `2026-10-21` (with the time, if it has one), a restored percentage as a plain number such as `0.4217`. Numbers are written with 16 significant digits, as in every copy, so a whole number above 9,007,199,254,740,992 comes back as text with its exact digits.
- **Markers in sheet names use parentheses**, as `(EMAIL_1)`, because Excel does not allow brackets in sheet names. `restore-file` reads them back.
- **A DOCX is rebuilt from paragraphs and tables.** Paragraph styles are kept where the style exists in a default document. Character formatting is not.
- **A PDF becomes a `.txt` file.** Name the output with `.txt`, or boxed stops with `a pdf is masked to a .txt file`. A scanned PDF has no text layer, so its copy is empty, and the pictures are not checked: without OCR, what an image shows is not covered. An encrypted PDF that needs a password stops with `the pdf is password protected`.

```text
$ boxed mask-file --scope doc-1 invoice.pdf invoice.masked.txt
pdf: invoice.pdf -> invoice.masked.txt
checked: text layer of 1 page
left out: images; annotations; attachments; document properties
markers: EMAIL 1, PHONE 1
complete: no - check what was left out before you send it
scope: doc-1
```

## Restore a file

Upload the copy, take the file the model returns and restore it with the same scope:

```text
$ boxed restore-file --scope deal-7 answer.csv answer.restored.csv
csv: answer.csv -> answer.restored.csv
checked: 5 rows, 7 columns
markers: EMAIL 4, PHONE 4
complete: yes
```

Options: `--scope NAME` is required and names the placeholders to put back. `--force` writes the file even when it holds unknown or odd placeholders (see below). `--replace` replaces an output file that already exists.

The model's file may have more columns or sheets than the copy had. boxed restores every placeholder it knows. The restored file is built from the model's file by the same rules as a masked copy, so the same things are left out of it. If the model writes formulas into a workbook, `restore-file` turns them into empty cells (see above). Ask for values.

Restore never guesses. When the model's file holds a placeholder boxed does not know, or one that looks changed, boxed writes nothing:

```text
$ boxed restore-file --scope deal-7 answer-odd.csv odd.restored.csv
not restored, check by hand: [EMAIL_42], PHONE_2
```

The exit code is 3 and there is no output file. Look at the file. When you accept the leftovers, add `--force`: boxed writes the file and keeps the unknown placeholders as they are (`[EMAIL_42]` stays in your file).

A masked PDF comes back as text. Restore the `.txt`:

```text
$ boxed restore-file --scope doc-1 invoice.masked.txt invoice.restored.txt
pdf: invoice.masked.txt -> invoice.restored.txt
checked: text
markers: EMAIL 1, PHONE 1
complete: yes
```

`restore-file` takes `.csv`, `.xlsx`, `.docx` and `.txt`. A `.pdf` is refused with `a pdf is restored from the .txt made from it`. It has no `--level`: restoring needs none.

## Safety rules

Both commands write a new file through a hidden part file and rename it into place. A failure leaves no half-written file. They refuse these cases and exit with code 2:

| Case | Message |
|---|---|
| The output is the source (also through a link) | `mask-file`: `the output would replace the source file`. `restore-file`: `the output is the input file: choose another output name` |
| The output already exists | `the output file exists already: name another file, delete it first, or add --replace to replace it` |
| The output is a link | `the output path is a link: name the file itself` |
| The output is inside the boxed folder | `the output is not written in the boxed home, where the journal, the vault and the keys are` |
| The folder of the output is missing | `the folder of the output file does not exist` |
| Level 4 | `level 4 sends the task and the table schema only: use boxed plan, or ask at a level from 0 to 3` |
| The scope is unknown (`restore-file`) | `unknown scope: boxed journal show lists the scopes in use (the scope field)` |
| A CSV whose delimiter cannot be told | `the delimiter of this csv file cannot be told for sure: name it (boxed mask-file --delimiter comma, semicolon, tab or pipe)` |
| A damaged file | `cannot process this xlsx file`, or `not UTF-8` for a CSV |

No message names a file or a scope: a name can say what is in it.

`--replace` replaces any plain file at the output name. It does not follow links.

boxed saves the placeholders in the vault only when the new file has been written, and the new file appears at the output name only after the placeholders are saved and the journal record is written: when the vault or the journal cannot be written, no copy is left, and with `--replace` the old file stays as it was. Every successful run writes one journal record (`manual`, `prepared` for mask, `received` for restore) with the format, whether the copy was complete, the counts and the hash of the new file, taken from the file before it is moved into place. It never holds the content.

## Limits

- **Masking does not stop inference from context.** Placeholders hide direct identifiers. A model can still guess who or what a file is about from what remains. Names and companies are found only with a name model (see [install.md](install.md)).
- **The copy is only as good as the detectors.** A value no detector knows stays visible. Read the copy before you upload it.
- **Left-out parts are not looked at.** An image, a comment or a hidden sheet may hold data. They are not in the copy, so they do not leave. boxed does not look inside them, so it cannot tell you what they hold.
- **No OCR.** Text in pictures is not read.
- **Uploads are yours.** boxed does not send the copy anywhere. Where you upload it, and what that service keeps, is your decision (see [privacy.md](privacy.md)). The browser extension masks text only and does not handle files.
- **To send a file's text through your API key, give `boxed ask` the original text** (a CSV works as it is). `ask` masks it by itself. Do not feed it an already masked copy.
