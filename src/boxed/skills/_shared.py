"""Two helpers that several modules of the skills package need, written once so that a fix reaches every user of them.

`escaped` spells out text that comes from disk (a folder name, a config key, a line of evidence) before a line shows it: a terminal
reads some characters as commands, and others hide themselves or forge a line. `no_repeated_keys` is the `object_pairs_hook` of every
strict read of JSON in the package. Neither needs anything else of the package, so any module can import them."""


def escaped(text: object) -> str:
    """`text` with every character that is not printable written out: \\xNN below 256, \\uNNNN below 65536, \\UNNNNNNNN above. That is
    every control character (Cc: an escape sequence, a line break, a cursor move), every format character (Cf: a right-to-left override,
    a zero-width space, a tag character), a lone surrogate (Cs), a line or paragraph separator (Zl, Zp), a space that is not the plain
    one (Zs: no-break, ideographic), a private-use character (Co) and one nobody has assigned yet (Cn). Ids are built with this spelling
    and are the keys of the record, so a spelling that has been in use does not change."""
    out = []
    for c in str(text):
        if c.isprintable():
            out.append(c)
        elif ord(c) < 0x100:
            out.append(f"\\x{ord(c):02x}")
        elif ord(c) < 0x10000:
            out.append(f"\\u{ord(c):04x}")
        else:
            out.append(f"\\U{ord(c):08x}")
    return "".join(out)


def no_repeated_keys(pairs: list[tuple[str, object]]) -> dict:
    """The `object_pairs_hook` of a strict read. A parser keeps the last of a key that stands twice, and the earlier one would hide in
    the file. The text of the ValueError is fixed and is never shown: each caller refuses in its own words."""
    if len({key for key, _ in pairs}) != len(pairs):
        raise ValueError("a key twice")
    return dict(pairs)
