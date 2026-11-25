import csv
import io
import ipaddress
import json
import re
import stat
from collections import Counter
from dataclasses import asdict

import pytest

from bench import metrics
from bench.generate import BenchDoc, generate
from bench.metrics import evaluate
from boxed.detect import Detection, detect
from boxed.detect.validators import iban_ok, luhn_ok
from boxed.mask import mask
from support import mode_is

LABEL_SHAPES = {
    "EMAIL": re.compile(r"^[^@\s]+@[^@\s]+\.[a-z]{2,}$"),
    "PHONE": re.compile(r"^(?:\+|8 )[\d ()\-]+$"),
    "IP": re.compile(r"^\d+\.\d+\.\d+\.\d+$"),
    "CARD": re.compile(r"^[\d ]{16,19}$"),
    "IBAN": re.compile(r"^DE\d{2}[\d ]+$"),
    "PRIVATE_KEY": re.compile(r"^-----BEGIN RSA PRIVATE KEY-----[\s\S]+-----END RSA PRIVATE KEY-----$"),
    "JWT": re.compile(r"^eyJ[\w-]+\.eyJ[\w-]+\.[\w-]+$"),
    "SECRET": re.compile(r"^\S{8,}$"),
    "PERSON": re.compile(r"^[^\W\d_]+(?: [^\W\d_]+)?$"),  # a first name, or a first name and a surname
    "ORG": re.compile(r"^[^\W\d_]+(?: [^\W\d_]+)*$"),  # the name without the legal form
}
NEW_GENRES = {"table_en", "table_ru", "contract_en", "contract_ru", "email_en", "email_ru", "mixed"}
CYRILLIC = re.compile(r"[А-Яа-яЁё]")
LATIN = re.compile(r"[A-Za-z]")
RESERVED_DOMAINS = {"example.com", "example.org", "example.net"}  # RFC 2606: no mailbox can exist there
DOCUMENTATION_NETWORKS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]  # RFC 5737
FICTIONAL_PHONE = re.compile(r"^(?:\+44 20 7946 0\d{3}|(?:\+7|8) \(000\) \d{3}-\d{2}-\d{2})$")  # Ofcom drama range; Russian area code 000
LEGAL_FORMS = {"Ltd", "LLC", "Inc", "GmbH", "ООО", "АО"}


def test_wilson_known_values():
    assert metrics.wilson(0, 500) == pytest.approx((0.0, 0.0076), abs=1e-4)
    assert metrics.wilson(5, 100) == pytest.approx((0.0215, 0.1118), abs=1e-4)
    assert metrics.wilson(100, 100)[1] == 1.0


def test_wilson_edge_cases():
    assert metrics.wilson(0, 0) == (0.0, 1.0)  # no documents: no information
    for k, n in [(-1, 10), (11, 10)]:
        with pytest.raises(ValueError):
            metrics.wilson(k, n)


def test_generator_is_deterministic():
    assert generate(1, 20) == generate(1, 20)
    assert generate(1, 20) != generate(2, 20)
    assert [d.genre for d in generate(1, 40)] == [d.genre for d in generate(1, 40)]
    assert {d.lang for d in generate(1, 40)} == {"en", "ru", "mixed"}


def test_genres_come_in_turn():
    docs = generate(1, 500)
    assert Counter(d.lang for d in docs) == {"en": 200, "ru": 200, "mixed": 100}
    assert set(Counter(d.genre for d in docs).values()) == {25, 100}  # eight genres per language, and the one mixed genre


def test_labels_match_their_text():
    for doc in generate(3, 120):
        assert doc.labels and doc.genre
        assert doc.genre == "mixed" or doc.genre.endswith("_" + doc.lang)
        for (start, end, kind), following in zip(doc.labels, doc.labels[1:] + [(len(doc.text), 0, "")]):
            value = doc.text[start:end]
            assert 0 <= start < end <= following[0] and value.strip() == value, (doc.genre, kind)
            assert LABEL_SHAPES[kind].match(value), (doc.genre, kind, value)
            if kind == "CARD":
                assert luhn_ok(value)
            if kind == "IBAN":
                assert iban_ok(value)


def test_generated_values_cannot_belong_to_anyone():
    for doc in generate(11, 400):
        assert doc.text.count("@") == sum(kind == "EMAIL" for _, _, kind in doc.labels), doc.genre  # no unlabelled address
        for start, end, kind in doc.labels:
            value = doc.text[start:end]
            if kind == "EMAIL":
                assert value.rsplit("@", 1)[1] in RESERVED_DOMAINS, value
            elif kind == "PHONE":
                assert FICTIONAL_PHONE.match(value), value
            elif kind == "IP":
                assert any(ipaddress.ip_address(value) in network for network in DOCUMENTATION_NETWORKS), value


def test_new_genres_and_categories_present():
    docs = generate(5, 200)
    assert NEW_GENRES <= {d.genre for d in docs}
    kinds = {kind for d in docs for _, _, kind in d.labels}
    for category, members in metrics.CATEGORIES.items():
        assert members <= kinds, (category, members - kinds)
    for doc in docs:
        has_cyrillic, has_latin = bool(CYRILLIC.search(doc.text)), bool(LATIN.search(doc.text))
        if doc.lang == "en":
            assert has_latin and not has_cyrillic, doc.genre
        if doc.lang == "ru":
            assert has_cyrillic, doc.genre
        if doc.lang == "mixed":
            assert has_cyrillic and has_latin, doc.genre


def test_tables_are_csv_and_labels_are_whole_cells():
    tables = [d for d in generate(5, 200) if d.genre.startswith("table_")]
    assert {d.genre for d in tables} == {"table_en", "table_ru"}
    for doc in tables:
        rows = list(csv.reader(io.StringIO(doc.text), delimiter="," if doc.lang == "en" else ";"))
        assert len(rows) >= 3 and len(rows[0]) >= 4
        assert {len(row) for row in rows} == {len(rows[0])}, doc.genre
        cells = {cell for row in rows for cell in row}
        assert all(doc.text[s:e] in cells for s, e, _ in doc.labels), doc.genre


def test_org_labels_never_include_the_legal_form():
    orgs = [doc.text[s:e] for doc in generate(5, 300) for s, e, kind in doc.labels if kind == "ORG"]
    assert len(orgs) > 100
    assert not any(LEGAL_FORMS & set(org.split()) for org in orgs)


def test_contracts_sometimes_cite_four_part_clause_numbers():
    """Real contracts do, and the rules read such a number as an IPv4 address: a false-positive trap for the detector."""
    docs = generate(5, 300)
    for genre, regex in {"contract_en": r"clause \d\.\d\.\d\.\d of", "contract_ru": r"п\. \d\.\d\.\d\.\d Приложения"}.items():
        found = [bool(re.search(regex, d.text)) for d in docs if d.genre == genre]
        assert any(found) and not all(found), genre


def test_russian_contracts_agree_in_gender_and_punctuation():
    docs = [d for d in generate(5, 600) if d.lang == "ru"]
    contracts = [d for d in docs if d.genre == "contract_ru"]
    assert len(contracts) >= 20
    for doc in contracts:
        start, end, kind = next(label for label in doc.labels if label[2] == "PERSON")  # the director, in the genitive
        female = doc.text[start:end].split()[-1].endswith("ой")
        assert ("действующей" in doc.text) == female and ("действующего" in doc.text) == (not female)
    assert not any(".." in d.text for d in docs)


class FixedNer:
    """NER stub returning given spans: enough to switch the measurement of names on."""

    def __init__(self, spans):
        self.spans = spans

    def find(self, text):
        return [Detection(start, end, kind, text[start:end], "ner:stub") for start, end, kind in self.spans]


class FakeClock:
    """A clock that moves only when a test advances it."""

    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now

    def advance_ms(self, ms):
        self.now += ms / 1000


def lose_the_first_email(text, detections, markers):
    """A masker that drops a value: nothing is left to restore it from."""
    return mask(text, detections, markers).replace("[EMAIL_1]", "", 1)


def test_evaluate_counts_misses():
    text = "mail anna@acme.io and secret XYZ"
    doc = BenchDoc(id="d1", lang="en", text=text, labels=[(5, 17, "EMAIL"), (29, 32, "SECRET")])
    report = evaluate([doc])
    assert report.docs == 1 and report.docs_with_critical_miss == 1
    assert report.recall_by_kind == {"EMAIL": 1.0, "SECRET": 0.0}
    row = report.by_lang["en"]
    assert (row.docs, row.docs_with_critical_miss, row.critical_miss_rate) == (1, 1, 1.0)
    assert row.values_by_category == {"secrets": 1, "identifiers": 1}
    assert row.misses_by_category == {"secrets": 1, "identifiers": 0}


@pytest.mark.parametrize(
    "text, labels",
    [
        ("zzzzzzzz a@example.com b@example.com", [(0, 8, "SECRET"), (9, 22, "EMAIL"), (23, 36, "EMAIL")]),  # the miss comes first
        ("a@example.com zzzzzzzz b@example.com", [(0, 13, "EMAIL"), (14, 22, "SECRET"), (23, 36, "EMAIL")]),  # in the middle
    ],
    ids=["first", "middle"],
)
def test_a_miss_before_covered_values_still_fails_the_document(text, labels):
    missed = BenchDoc("d1", "en", text, labels)
    clean = BenchDoc("d2", "en", "write to c@example.com", [(9, 22, "EMAIL")])
    for docs in ([missed, clean], [clean, missed]):  # the verdict is per document, whatever its neighbours
        row = evaluate(docs).by_lang["en"]
        assert (row.docs, row.docs_with_critical_miss, row.critical_miss_rate) == (2, 1, 0.5)


@pytest.mark.parametrize(
    "kind, category",
    [
        ("SECRET", "secrets"),
        ("PRIVATE_KEY", "secrets"),
        ("JWT", "secrets"),
        ("EMAIL", "identifiers"),
        ("PHONE", "identifiers"),
        ("CARD", "identifiers"),
        ("IBAN", "identifiers"),
    ],
)
def test_a_missed_value_of_every_critical_kind_fails_the_document(kind, category):
    report = evaluate([BenchDoc("d1", "en", "nothing detectable here", [(0, 7, kind)])])
    assert report.docs_with_critical_miss == 1
    assert report.by_lang["en"].misses_by_category[category] == 1


def test_a_missed_ip_is_reported_but_not_critical():
    doc = BenchDoc("d1", "en", "gateway 10.0.0.1x", labels=[(8, 17, "IP")])  # the detector stops before the "x"
    report = evaluate([doc])
    assert report.recall_by_kind == {"IP": 0.0}
    assert report.docs_with_critical_miss == 0 and set(report.by_lang["en"].misses_by_category) == {"secrets", "identifiers"}


def test_recall_is_rounded_to_four_places():
    text = "a@example.com b@example.com plain"
    doc = BenchDoc("d1", "en", text, labels=[(0, 13, "EMAIL"), (14, 27, "EMAIL"), (28, 33, "EMAIL")])
    assert evaluate([doc]).recall_by_kind == {"EMAIL": 0.6667}


def test_a_value_counts_as_covered_by_a_detection_of_another_kind():
    token = "eyJ" + "a" * 10 + ".eyJ" + "b" * 10 + "." + "c" * 10
    text = f"Authorization: Bearer {token}"
    assert [d.kind for d in detect(text)] == ["SECRET"]  # the premise: the bearer rule, not the JWT rule, claims the token
    report = evaluate([BenchDoc("d1", "en", text, [(text.index(token), len(text), "JWT")])])
    assert report.recall_by_kind == {"JWT": 1.0} and report.docs_with_critical_miss == 0


def test_evaluate_counts_false_positives():
    doc = BenchDoc(id="d2", lang="ru", text="пишите на ivan@acme.io", labels=[])
    report = evaluate([doc])
    assert report.false_positives_by_kind == {"EMAIL": 1}
    assert report.docs_with_critical_miss == 0


def test_false_positives_counted_on_a_crafted_doc():
    two_addresses = BenchDoc("d1", "en", "mail a@example.com from 10.1.2.3 via 10.1.2.4", labels=[(5, 18, "EMAIL")])
    clean = BenchDoc("d2", "en", "write to b@example.com", labels=[(9, 22, "EMAIL")])
    report = evaluate([two_addresses, clean])
    row = report.by_lang["en"]
    assert (row.false_positives, row.false_positives_per_doc) == (2, 1.0)
    assert report.false_positives_by_kind == {"IP": 2}
    assert row.docs_with_critical_miss == 0  # a false positive is not a miss


@pytest.mark.parametrize(
    "text, label",
    [
        ("Maria a@example.com", (0, 6, "SECRET")),  # the label ends where the address begins
        ("10.0.0.1x", (8, 9, "SECRET")),  # the address ends where the label begins
    ],
    ids=["label-then-detection", "detection-then-label"],
)
def test_a_detection_that_only_touches_a_label_is_a_false_positive(text, label):
    assert evaluate([BenchDoc("d1", "en", text, [label])]).by_lang["en"].false_positives == 1


def test_round_trip_errors_counted():
    doc = BenchDoc("d1", "en", "write to a@example.com today", labels=[(9, 22, "EMAIL")])
    assert evaluate([doc]).by_lang["en"].restore_errors == 0
    row = evaluate([doc], masker=lose_the_first_email).by_lang["en"]
    assert (row.restore_errors, row.restore_errors_per_doc) == (1, 1.0)


def test_ambiguous_places_are_counted_per_place():
    doc = BenchDoc("d1", "en", "write ivan@example.com about EMAIL_1 and EMAIL_2", labels=[(6, 22, "EMAIL")])
    row = evaluate([doc, BenchDoc("d2", "en", "nothing here", [])]).by_lang["en"]
    assert (row.ambiguous_places, row.ambiguous_per_doc) == (2, 1.0)  # two places in one document, none in the other
    assert row.restore_errors == 0  # the text still comes back as it was: the places are only flagged


def test_people_and_organizations_are_measured_only_with_ner():
    doc = BenchDoc("d1", "en", "Maria Garcia works at Valtrix Systems", labels=[(0, 12, "PERSON"), (22, 37, "ORG")])
    without = evaluate([doc])
    assert not without.ner and set(without.by_lang["en"].misses_by_category) == {"secrets", "identifiers"}
    assert without.recall_by_kind == {}
    assert not evaluate([doc], ner=[]).ner  # an empty list of detectors is no NER either
    with_ner = evaluate([doc], ner=[FixedNer([(0, 12, "PERSON")])])
    row = with_ner.by_lang["en"]
    assert with_ner.ner and row.values_by_category["people"] == 1
    assert (row.misses_by_category["people"], row.misses_by_category["organizations"]) == (0, 1)
    assert with_ner.recall_by_kind == {"PERSON": 1.0, "ORG": 0.0}
    assert without.docs_with_critical_miss == with_ner.docs_with_critical_miss == 0  # names are never critical


def test_time_per_document_is_median_and_p95_of_unsorted_times(monkeypatch):
    clock = FakeClock()
    monkeypatch.setattr(metrics, "perf_counter", clock)
    # 21 documents, in no order; sorted, the 11th is 6 and the 20th is 11, and the mean (24.3) is far from both
    durations = iter([5, 1, 3, 2, 4, 6, 8, 7, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 400, 11])

    def masker(text, detections, markers):
        clock.advance_ms(next(durations))
        return mask(text, detections, markers)

    docs = [BenchDoc(f"d{i}", "en", "plain text", []) for i in range(21)]
    row = evaluate(docs, masker=masker).by_lang["en"]
    assert (row.time_ms_median, row.time_ms_p95) == (6.0, 11.0)


def test_time_covers_detect_and_mask_but_not_restore(monkeypatch):
    clock = FakeClock()
    monkeypatch.setattr(metrics, "perf_counter", clock)
    real_detect, real_restore = metrics.detect, metrics.restore

    def slow_detect(*args, **kwargs):
        clock.advance_ms(3)
        return real_detect(*args, **kwargs)

    def slow_masker(text, detections, markers):
        clock.advance_ms(4)
        return mask(text, detections, markers)

    def slow_restore(*args, **kwargs):
        clock.advance_ms(50)
        return real_restore(*args, **kwargs)

    monkeypatch.setattr(metrics, "detect", slow_detect)
    monkeypatch.setattr(metrics, "restore", slow_restore)
    row = evaluate([BenchDoc("d1", "en", "plain text", [])], masker=slow_masker).by_lang["en"]
    assert row.time_ms_median == row.time_ms_p95 == 7.0


def test_level_reaches_the_detector():
    doc = BenchDoc("d1", "en", "write to a@example.com", labels=[(9, 22, "EMAIL")])
    assert evaluate([doc], level=2).docs_with_critical_miss == 0
    hidden = evaluate([doc], level=0)  # level 0 leaves e-mail addresses alone
    assert hidden.level == 0 and hidden.docs_with_critical_miss == 1


def test_report_json_has_intervals():
    report = evaluate(generate(3, 40))
    data = json.loads(json.dumps(asdict(report)))
    assert data["ner"] is False and set(data["by_lang"]) == {"en", "ru", "mixed"}
    for row in data["by_lang"].values():
        low, high = row["critical_miss_interval"]
        assert 0.0 <= low <= row["critical_miss_rate"] <= high <= 1.0
        assert [low, high] == pytest.approx(metrics.wilson(row["docs_with_critical_miss"], row["docs"]), abs=1e-4)


def test_cli_prints_the_json_report(capsys):
    metrics.main(["--seed", "3", "--docs", "10"])
    data = json.loads(capsys.readouterr().out)
    assert (data["seed"], data["docs"], data["level"], data["ner"]) == (3, 10, 2, False)


def test_cli_level_flag_reaches_the_report(capsys):
    metrics.main(["--seed", "3", "--docs", "10", "--level", "0"])
    data = json.loads(capsys.readouterr().out)
    assert data["level"] == 0 and data["docs_with_critical_miss"] > 0  # at level 0 e-mail, phone and IBAN stay unmasked


def test_cli_json_flag_writes_a_private_file_instead_of_printing(tmp_path, capsys):
    path = tmp_path / "report.json"
    metrics.main(["--seed", "3", "--docs", "10", "--json", str(path)])
    assert capsys.readouterr().out == ""
    assert json.loads(path.read_text())["docs"] == 10
    assert mode_is(path, 0o600)
    assert not (tmp_path / "report.json.part").exists()


def test_cli_json_flag_replaces_an_old_report_and_survives_a_stale_part_file(tmp_path):
    path = tmp_path / "report.json"
    path.write_text("old")
    path.chmod(0o644)
    (tmp_path / "report.json.part").write_text("left behind by a crash")
    metrics.main(["--seed", "3", "--docs", "10", "--json", str(path)])
    assert json.loads(path.read_text())["docs"] == 10 and mode_is(path, 0o600)


def test_cli_ner_flag_measures_people_and_organizations(monkeypatch, capsys):
    monkeypatch.setattr(metrics, "_load_ner", lambda: [FixedNer([])])
    metrics.main(["--seed", "3", "--docs", "10", "--ner"])
    data = json.loads(capsys.readouterr().out)
    assert data["ner"] is True and {"people", "organizations"} <= set(data["by_lang"]["en"]["misses_by_category"])


@pytest.mark.parametrize(
    "error",
    [ImportError("no natasha here"), OSError("no model in /some/cache"), RuntimeError("out of memory"), ValueError("bad config")],
    ids=["ImportError", "OSError", "RuntimeError", "ValueError"],
)
def test_cli_ner_that_does_not_load_measures_nothing(monkeypatch, capsys, error):
    def broken():
        raise error

    monkeypatch.setattr(metrics, "_load_ner", broken)
    with pytest.raises(SystemExit) as stopped:
        metrics.main(["--docs", "10", "--ner"])
    captured = capsys.readouterr()
    assert stopped.value.code == 2 and captured.out == ""
    assert f"NER did not load ({type(error).__name__})" in captured.err and str(error) not in captured.err
