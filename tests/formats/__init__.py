"""Helpers for the format tests: look for original values in every part of an output file."""

import zipfile
from pathlib import Path


def parts_of(path: Path) -> dict[str, bytes]:
    """Name -> bytes of every zip part; a plain file is one part."""
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            return {name: archive.read(name) for name in archive.namelist()}
    return {path.name: path.read_bytes()}


def assert_clean(path: Path, *values: str) -> None:
    """No value in any part, in a part name or in the raw bytes of the file."""
    blobs = {**parts_of(path), "<raw file>": path.read_bytes(), "<part names>": "\n".join(parts_of(path)).encode()}
    for value in values:
        for name, blob in blobs.items():
            assert value.encode() not in blob, f"{value!r} found in {name}"


# what LibreOffice writes into docProps/custom.xml of a file that has no custom properties
EMPTY_CUSTOM_PROPERTIES = (
    b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
    b'<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/custom-properties"'
    b' xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes"></Properties>'
)


def rewrite_zip(path: Path, changes) -> None:
    """Change, add or drop zip parts: changes maps a part name to a function of its old bytes (b"" when the part is new),
    or to None to drop the part."""
    with zipfile.ZipFile(path) as archive:
        parts = {name: archive.read(name) for name in archive.namelist()}
    for name, change in changes.items():
        if change is None:
            del parts[name]
        else:
            parts[name] = change(parts.get(name, b""))
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in parts.items():
            archive.writestr(name, data)
