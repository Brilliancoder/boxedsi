# boxed-bench v1

Synthetic EN, RU and mixed EN/RU documents; every secret and personal value is labelled when the text is written. Genres: logs, `.env`-style configs, code, call transcripts, private keys, CSV tables, contracts, emails, and mixed texts (Russian sentences with Latin names, English sentences with Russian names). Genres come in turn, so 500 documents are 200 EN, 200 RU and 100 mixed. The values are made up, but only some come from ranges reserved for examples: e-mail domains are example.com, .org and .net, IPs are documentation ranges, UK numbers are Ofcom's drama range, Russian numbers use the area code 000. Names are common first names and surnames combined at random, companies are ordinary words combined (a real company may share a name), cards and IBANs are random with valid check digits, keys and passwords are random.

```bash
uv run python -m bench.metrics --seed 7 --docs 500 [--level N] [--ner] [--json PATH]
```

`--json PATH` writes the report (mode 600) instead of printing it. `--ner` also measures people and organizations; run it with `uv run --extra ner-ru --extra ner-en` and the models in the local cache (Natasha, and GLiNER `urchade/gliner_multi_pii-v1`, about 1 GB); set `HF_HUB_OFFLINE=1` to be sure nothing is downloaded. Both run on every document, as `ner = ["ru", "en"]` in `boxed.toml` does. A model that does not load stops the run with exit code 2 and nothing is measured.

## What is measured, per language (en, ru, mixed)

- **Documents with a critical miss** - the main metric, with a 95% Wilson interval. A document fails if any secret (SECRET, PRIVATE_KEY, JWT) or identifier (EMAIL, PHONE, CARD, IBAN) is not fully covered by one detection of any kind.
- **Misses by category** - labelled values not fully covered. People (PERSON) and organizations (ORG) only with `--ner`; they are reported apart and never count as critical. IP is in `recall_by_kind` only.
- **False positives per document** - detections that overlap no label. The generator writes few things that look sensitive and are not (clause numbers, speaker labels), so this is a floor, not an estimate for real documents.
- **Restore errors** - documents that differ from the original after mask and restore. Restore runs on the masked text itself, so this checks mask and restore against each other; it says nothing about a model that alters placeholders. **Ambiguous places** per document - suspicious markers that restore reports.
- **Time** - median and 95th percentile of detect plus mask for one document, one thread, models already loaded.

## Result, 2026-10-21, level 2, seed 7, 500 documents, after the detector fixes

Rules only:

| | EN (200) | RU (200) | mixed (100) |
|---|---|---|---|
| Documents with a critical miss | 0 (0%, interval 0-1.9%) | 0 (0%, interval 0-1.9%) | 0 (0%, interval 0-3.7%) |
| Secrets missed | 0 of 168 | 0 of 183 | 0 of 73 |
| Identifiers missed | 0 of 635 | 0 of 638 | 0 of 473 |
| False positives per document | 0 | 0 | 0 |
| Restore errors, ambiguous places | 0, 0 | 0, 0 | 0, 0 |
| Time per document, median / p95 | 0.10 / 0.33 ms | 0.11 / 0.54 ms | 0.25 / 0.29 ms |

With `--ner` the critical rows are the same; names are added:

| | EN | RU | mixed |
|---|---|---|---|
| People missed | 37 of 345 | 11 of 345 | 0 of 400 |
| Organizations missed | 0 of 166 | 0 of 165 | 0 of 327 |
| False positives per document | 0 | 0 | 0 |
| Time per document, median / p95 | 66 / 130 ms | 71 / 169 ms | 90 / 122 ms |

Times are one run on a laptop with other jobs running. At `--docs 2000`, rules only, EN is 0 of 800 (interval 0-0.5%), RU 0 of 800 (0-0.5%), mixed 0 of 400 (0-1.0%).

Before the fixes (the first run of v1, same seed and size) RU had 15 documents with a critical miss of 200 (7.5%, interval 4.6-12.0%; 46 of 800 at 2,000 documents), the rules had 0.055 (EN) and 0.060 (RU) false positives per document, and NER had 0.305 and 0.310.

## What the numbers say

The causes below were found by listing the failing documents; the report itself does not break results down by genre.

- All 15 RU critical misses of the first run were the password in the Russian access letter ("Пароль: ..."): the key-value rule knew English names only. The rule now knows the Russian ones, and none is missed. **Read this with care: the generator writes exactly that form, one line "Пароль: ..." in the access letter, and the fix targets that form.** 0 of 200 shows the fix works on it, not that Russian secrets are found in general. Checked by hand with the detector: "Пароль - ..." and "Пароль от почты: ..." are found; a name of three or more words before the colon ("Пароль администратора базы данных: ...") and a table row ("| Пароль | ... |") are not.
- The 23 rule false positives of the first run were four-part clause references in contracts ("clause 4.3.1.2" read as an IPv4 address). A dotted quad right after a clause word is no longer an IP, and the speaker labels of transcripts ("Speaker 1", "Спикер 1") are no longer people: that was all 100 PERSON false positives. The generator writes few look-alikes, so 0 is a floor, not a promise for real documents.
- With NER, all 48 missed people (37 EN, 11 RU) are first names standing alone ("Hi Henry,"); no full name was missed.
- Natasha, a Russian model, also runs on English text and returns wide spans, for example "Stonebridge Holdings LLC (Sophie Smith" for a company and a person (seen by hand in this run; the report does not measure span width). The longest-first resolver keeps such a span over any shorter GLiNER span inside it. A span that covers a label counts as a hit, so this over-masking is invisible here.
- 200 documents per language cannot show the target (at most 1% EN, 2% RU): even with no misses the interval reaches 1.9%. That takes about 380 documents per language for 1% and about 190 for 2%.

## What v1 does not show

- No closed hand-labelled set of real documents yet. Without it the numbers are a regression and gap probe, not real-world recall.
- No task-success metric: it needs a model.
- Most values come in the formats the rules were built for. Not generated: phone numbers without "+" or brackets, passwords in prose ("the password is ..."), values split across lines, OCR noise, Russian bank details (account, BIK, KPP, OGRN), addresses, patronymics and initials, Russian cases other than nominative and genitive, Russian passwords after a longer name or in a table row, German, French and Spanish, commercial facts (amounts, percentages, dates: the generator does not label them, so level 3 is not measured), marker-like text in the originals (so ambiguous places stay at 0; a crafted test covers the counter).
- Documents are 125 to 1,104 characters, so input limits of the NER models and speed on large files are not exercised.
- A detection that covers a label and much more text is a hit, not a false positive (see above).
