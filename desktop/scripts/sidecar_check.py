"""Talks to `boxed serve` the way the shell does and checks a built sidecar end to end. Standard library only.

    python3 sidecar_check.py PATH_TO_SIDECAR

Run by build-sidecar.py right after a build and by smoke-bundle.py on the sidecar inside the app. Every check uses made-up data,
a throwaway boxed home and the file key store (BOXED_KEYSTORE=insecure-file: the real keychain is never touched), and a PATH
that holds nothing, so a sidecar that quietly depended on a Python of the machine would fail here.
"""

from __future__ import annotations

import json
import os
import struct
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

EMAIL = "ivan.petrov@example.com"
KEY = "AKIAIOSFODNN7EXAMPLE"
NAME = "Иван Петров Сергеевич"  # found only by the Russian name model (ner-ru), at level 1 and above
COMPANY = "Ромашка"  # in ООО "Ромашка": a company, found by the same model at level 2 and above
LINES = [f"Contact: {EMAIL}, phone +7 916 123-45-67", f"Key: {KEY}"]
RUSSIAN = f"{NAME} подписал договор с ООО \"{COMPANY}\"."
TEXT = "\n".join(LINES)

CONTENT_TYPES = "http://schemas.openxmlformats.org/package/2006/content-types"
RELATIONSHIPS = "http://schemas.openxmlformats.org/package/2006/relationships"
OFFICE_DOCUMENT = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"
MAIN = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
WORD = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"


def encode(message: dict) -> bytes:
    body = json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return struct.pack("<I", len(body)) + body


def read_frame(stream) -> dict | None:
    header = stream.read(4)
    if not header:
        return None
    assert len(header) == 4, "truncated header"
    (size,) = struct.unpack("<I", header)
    body = stream.read(size)
    assert len(body) == size, "truncated body"
    return json.loads(body.decode("utf-8"))


class Serve:
    """One `serve` process; ask() sends a request and returns the reply without its id."""

    def __init__(self, exe: Path, env: dict) -> None:
        self.process = subprocess.Popen([str(exe), "serve"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env)
        self.next_id = 1

    def ask(self, cmd: str, **fields) -> dict:
        request = {"id": self.next_id, "cmd": cmd, **fields}
        self.next_id += 1
        self.process.stdin.write(encode(request))
        self.process.stdin.flush()
        reply = read_frame(self.process.stdout)
        assert reply is not None, f"{cmd}: the sidecar closed its output"
        assert reply.pop("id", None) == request["id"], f"{cmd}: the reply answers another request"
        return reply

    def close(self) -> int:
        """End of input, as the shell does it on exit; the exit code."""
        self.process.stdin.close()
        return self.process.wait(timeout=30)


def clean_env(root: Path) -> dict:
    """No Python anywhere: PATH is an empty folder. The boxed home and the key store are throwaway."""
    nothing = root / "empty-path"
    nothing.mkdir(exist_ok=True)
    env = {"PATH": str(nothing), "HOME": str(root), "BOXED_HOME": str(root / "boxed-home"), "BOXED_KEYSTORE": "insecure-file"}
    env["BOXED_SERVE_NER"] = "ru"  # what the shell sets for its sidecar (desktop/src-tauri/src/lib.rs): the Russian name model on
    for name in ("SystemRoot", "SYSTEMROOT", "TEMP", "TMP"):  # Windows will not start a process without them
        if name in os.environ:
            env[name] = os.environ[name]
    return env


def escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def write_zip(path: Path, parts: dict[str, str]) -> None:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in parts.items():
            archive.writestr(name, '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' + content)


def write_xlsx(path: Path) -> None:
    rows = "".join(
        f'<row r="{n}"><c r="A{n}" t="inlineStr"><is><t>{escape(line)}</t></is></c></row>' for n, line in enumerate([*LINES, RUSSIAN], start=1)
    )
    write_zip(
        path,
        {
            "[Content_Types].xml": f'<Types xmlns="{CONTENT_TYPES}"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
            '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>',
            "_rels/.rels": f'<Relationships xmlns="{RELATIONSHIPS}"><Relationship Id="rId1" Type="{OFFICE_DOCUMENT}" Target="xl/workbook.xml"/></Relationships>',
            "xl/workbook.xml": f'<workbook xmlns="{MAIN}" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
            '<sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets></workbook>',
            "xl/_rels/workbook.xml.rels": f'<Relationships xmlns="{RELATIONSHIPS}"><Relationship Id="rId1" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>',
            "xl/worksheets/sheet1.xml": f'<worksheet xmlns="{MAIN}"><sheetData>{rows}</sheetData></worksheet>',
        },
    )


def write_docx(path: Path) -> None:
    paragraphs = "".join(f"<w:p><w:r><w:t>{escape(line)}</w:t></w:r></w:p>" for line in [*LINES, RUSSIAN])
    write_zip(
        path,
        {
            "[Content_Types].xml": f'<Types xmlns="{CONTENT_TYPES}"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>',
            "_rels/.rels": f'<Relationships xmlns="{RELATIONSHIPS}"><Relationship Id="rId1" Type="{OFFICE_DOCUMENT}" Target="word/document.xml"/></Relationships>',
            "word/document.xml": f'<w:document xmlns:w="{WORD}"><w:body>{paragraphs}</w:body></w:document>',
        },
    )


def write_pdf(path: Path) -> None:
    stream = "BT /F1 12 Tf 72 720 Td 16 TL " + " T* ".join(f"({line}) Tj" for line in LINES) + " ET"
    objects = [
        "<< /Type /Catalog /Pages 2 0 R >>",
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
        f"<< /Length {len(stream)} >>\nstream\n{stream}\nendstream",
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for number, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{number} 0 obj\n{body}\nendobj\n".encode()
    xref = len(out)
    out += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode()
    for offset in offsets:
        out += f"{offset:010d} 00000 n \n".encode()
    out += f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    path.write_bytes(bytes(out))


def everything_in(path: Path) -> bytes:
    """The bytes of a clean copy, with the zip parts of an Office file unpacked, to look for what must not be there."""
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            return b"".join(archive.read(name) for name in archive.namelist())
    return path.read_bytes()


def check(exe: Path) -> list[str]:
    """Runs the checks; returns one line per check that passed, raises AssertionError on the first that did not."""
    done: list[str] = []
    with tempfile.TemporaryDirectory(prefix="boxed-check-") as folder:
        root = Path(folder)
        serve = Serve(exe, clean_env(root))
        try:
            reply = serve.ask("ping")
            assert reply["ok"] is True and isinstance(reply["version"], str), reply
            assert reply["ner"] == ["ru"], f"the Russian name model is not on: {reply}"
            assert reply["ner_installed"] == ["ru"], f"the build carries the Russian model and not the English one: {reply}"
            done.append(f"ping: version {reply['version']}; the Russian name model runs, the English one is not in the build")

            masked = serve.ask("mask", text=TEXT, level=1)
            assert masked["ok"] is True, masked
            assert EMAIL not in masked["text"] and KEY not in masked["text"], "an original survived masking"
            done.append("mask: the e-mail address and the key are gone from the text")

            people = serve.ask("mask", text=RUSSIAN, level=1)
            assert people["ok"] is True and NAME not in people["text"], f"a Russian name survived level 1: {people}"
            company = serve.ask("mask", text=RUSSIAN, level=2)
            assert company["ok"] is True and COMPANY not in company["text"] and NAME not in company["text"], f"level 2: {company}"
            done.append("mask: a Russian full name is gone at level 1, the company too at level 2 (the name model works in the frozen build)")

            restored = serve.ask("restore", text=masked["text"], scope=masked["scope"])
            assert restored["ok"] is True and restored["text"] == TEXT, restored
            assert restored["unknown"] == [] and restored["suspicious"] == [], restored
            done.append("restore: the original text is back, no placeholder left over")

            # the masks of a working session share a scope: a placeholder stays one thing across them, and one answer restores both
            anna = serve.ask("mask", text="Write to anna@example.com", level=1, scope="session-check")
            boris = serve.ask("mask", text="Write to boris@example.com", level=1, scope=anna["scope"])
            assert anna["text"] == "Write to [EMAIL_1]" and boris["text"] == "Write to [EMAIL_2]", (anna, boris)
            both = serve.ask("restore", text=f"{anna['text']} / {boris['text']}", scope=anna["scope"])
            assert both["text"] == "Write to anna@example.com / Write to boris@example.com", both
            done.append("scope: two masks in one scope get different placeholders, and one answer restores both")

            reply = serve.ask("restore", text="[EMAIL_1]", scope="no-such-scope")
            assert reply == {"ok": False, "error": "unknown scope"}, reply
            reply = serve.ask("ping", surprise=1)
            assert reply["ok"] is False and reply["error"] == "bad request", reply
            done.append("refusals: an unknown scope and an unknown field get their fixed sentences")

            for name, writer, expect_gone in (
                ("sample.xlsx", write_xlsx, (EMAIL, KEY, NAME)),
                ("sample.docx", write_docx, (EMAIL, KEY, NAME)),
                ("sample.pdf", write_pdf, (EMAIL, KEY)),
            ):
                source = root / name
                writer(source)
                target = root / ("clean-" + name + (".txt" if name.endswith(".pdf") else ""))
                reply = serve.ask("mask-file", src=str(source), dest=str(target), level=1)
                assert reply["ok"] is True, f"{name}: {reply}"
                leftovers = [original for original in expect_gone if original.encode() in everything_in(target)]
                assert not leftovers, f"{name}: still holds {leftovers}"
                done.append(f"mask-file {name}: clean copy written")

            code = serve.close()
            assert code == 0, f"exit code {code} after end of input"
            done.append("end of input: exit code 0")
        finally:
            if serve.process.poll() is None:
                serve.process.kill()
    return done


if __name__ == "__main__":
    for line in check(Path(sys.argv[1])):
        print("ok -", line)
