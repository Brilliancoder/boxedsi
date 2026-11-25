"""CRYPTO_ADDR: a Bitcoin or Ethereum address whose own checksum holds (level 2, category finance).

Bitcoin: base58check addresses of a main net (P2PKH, starting with 1, and P2SH, starting with 3; the Bitcoin wiki, "Base58Check
encoding" and "Technical background of version 1 Bitcoin addresses") and bech32 / bech32m addresses of the main net (BIP-173 and
BIP-350, with their test vectors). Ethereum: 0x and 40 hex digits, and when the letters are of both cases the capitals must
follow the checksum of EIP-55 (a Keccak-256 hash; not the SHA3-256 of the standard library, whose padding differs). Addresses of
test nets and of other coins are left alone. All other addresses here are generated from random bytes."""

import hashlib
import random

import pytest

from boxed.detect import KINDS_BY_LEVEL, detect
from boxed.detect import patterns
from boxed.detect.patterns import Rule, _keccak256, rule_candidates

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def found(text, level=2):
    return [(d.kind, d.text) for d in detect(text, level=level)]


def kinds(text, level=2):
    return [kind for kind, _ in found(text, level)]


def openssl_keccak(data):
    try:
        return hashlib.new("keccak-256", data).digest()
    except ValueError:
        return None


# --- generators, from the specifications


def b58check(version, payload):
    data = bytes([version]) + payload
    data += hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]
    n, out = int.from_bytes(data, "big"), ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + out


def bech32_polymod(values):
    generator = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= generator[i] if (top >> i) & 1 else 0
    return chk


def to_5_bits(data):
    acc = bits = 0
    out = []
    for b in data:
        acc, bits = (acc << 8) | b, bits + 8
        while bits >= 5:
            bits -= 5
            out.append((acc >> bits) & 31)
    if bits:
        out.append((acc << (5 - bits)) & 31)
    return out


def segwit(version, program):
    const = 1 if version == 0 else 0x2BC830A3
    data = [version] + to_5_bits(program)
    mod = bech32_polymod([3, 3, 0, 2, 3] + data + [0] * 6) ^ const
    return "bc1" + "".join(BECH32[d] for d in data + [(mod >> 5 * (5 - i)) & 31 for i in range(6)])


def eip55(address_lower):
    digest = openssl_keccak(address_lower.encode()).hex()
    return "0x" + "".join(c.upper() if c.isalpha() and int(digest[i], 16) >= 8 else c for i, c in enumerate(address_lower))


# --- Bitcoin, base58check

BASE58_VECTORS = [
    "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs",  # the worked example of the Bitcoin wiki
]


@pytest.mark.parametrize("address", BASE58_VECTORS)
def test_a_base58check_address_of_the_wiki(address):
    assert found(f"Send it to {address} please") == [("CRYPTO_ADDR", address)]


@pytest.mark.parametrize("version", [0, 5])
def test_generated_base58check_addresses(version):
    rng = random.Random(version)
    for _ in range(80):
        address = b58check(version, bytes(rng.randrange(256) for _ in range(20)))
        assert address[0] == "1" if version == 0 else "3"
        assert found(f"pay {address}.") == [("CRYPTO_ADDR", address)], address


def test_an_address_with_leading_zero_bytes_is_found():
    for payload in (b"\0" + bytes(range(1, 20)), b"\0\0" + bytes(range(2, 20)), bytes(20)):
        address = b58check(0, payload)
        assert address.startswith("11")
        assert found(address) == [("CRYPTO_ADDR", address)]


def test_a_wrong_character_breaks_a_base58check_address():
    rng = random.Random(7)
    for _ in range(25):
        address = b58check(rng.choice((0, 5)), bytes(rng.randrange(256) for _ in range(20)))
        for i in range(1, len(address)):
            other = B58[(B58.index(address[i]) + 1 + rng.randrange(57)) % 58]
            assert "CRYPTO_ADDR" not in kinds(address[:i] + other + address[i + 1 :]), (address, i)


@pytest.mark.parametrize(
    "text",
    [
        "m" + "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs"[1:],  # a test net starts with m or n, or 2
        "LQ" + "PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs",  # another coin
        "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUA",  # a character short
        "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAsX",  # a character long
        "x1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs",
        "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs1",
        "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs0",
        "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUOs",  # O is no base58 character
        "1" * 34,
        "1" + "A" * 33,
    ],
)
def test_no_base58check_address(text):
    assert "CRYPTO_ADDR" not in kinds(text)


# --- Bitcoin, bech32 and bech32m

SEGWIT_VALID = [
    "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
    "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
    "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y",
    "BC1SW50QGDZ25J",
    "bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs",
    "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
]
SEGWIT_INVALID = [
    "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",  # a wrong checksum
    "BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2",  # witness version 17
    "bc1rw5uspcuh",  # a program of 1 byte
    "bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90",  # 41 bytes
    "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P",  # version 0 with 16 bytes
    "bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du",  # more than 4 bits of zero padding
    "bc1gmk9yu",  # no data
    "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd",  # the bech32 checksum where bech32m is due
    "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh",  # the bech32m checksum where bech32 is due
    "bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4",  # a character that is no bech32 one in the checksum
    "bc1pw5dgrnzv",  # 1 byte
    "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav253zgeav",  # 41 bytes
    "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf",  # more than 4 bits of zero padding
    "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7kv8f3t4",  # both cases
    "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",  # a test net
    "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
]


@pytest.mark.parametrize("address", SEGWIT_VALID)
def test_the_valid_segwit_addresses_of_the_bips(address):
    assert found(f"deposit: {address}") == [("CRYPTO_ADDR", address)]


@pytest.mark.parametrize("address", SEGWIT_INVALID)
def test_the_invalid_segwit_addresses_of_the_bips(address):
    assert "CRYPTO_ADDR" not in kinds(f"deposit: {address}")


def test_generated_segwit_addresses_and_a_wrong_character_in_each():
    rng = random.Random("segwit")
    for _ in range(30):
        for version, size in ((0, 20), (0, 32), (1, 32), (2, 24), (16, 2)):
            address = segwit(version, bytes(rng.randrange(256) for _ in range(size)))
            assert found(f"to {address}") == [("CRYPTO_ADDR", address)], address
            i = rng.randrange(3, len(address))
            other = rng.choice([c for c in BECH32 if c != address[i]])
            assert "CRYPTO_ADDR" not in kinds(address[:i] + other + address[i + 1 :])


# --- Ethereum

ETH_ALL_CAPS = ["0x52908400098527886E0F7030069857D2E4169EE7", "0x8617E340B3D01FA5F11F306F4090FD50E238070D"]
ETH_ALL_LOWER = ["0xde709f2102306220921060314715629080e2fb77", "0x27b1fdb04752bbc536007a920d24acb045561c26"]
ETH_CHECKSUMMED = [
    "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
    "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
    "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
    "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
]


@pytest.mark.parametrize("address", ETH_ALL_CAPS + ETH_ALL_LOWER + ETH_CHECKSUMMED)
def test_the_test_vectors_of_eip_55(address):
    assert found(f"wallet {address}, ok") == [("CRYPTO_ADDR", address)]


@pytest.mark.parametrize("address", ETH_CHECKSUMMED)
def test_a_changed_case_breaks_an_eip_55_address(address):
    for i, c in enumerate(address):
        if c.isalpha() and i >= 2:
            changed = address[:i] + c.swapcase() + address[i + 1 :]
            assert "CRYPTO_ADDR" not in kinds(changed), changed


@pytest.mark.parametrize(
    "text",
    [
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAe",  # 39 digits
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAedd",  # 41
        "x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        "5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",  # no 0x: a hash, as likely
        "0X5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        "a0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAedg",
        "0x" + "ab" * 32,  # a hash of 32 bytes
        "0xde709f2102306220921060314715629080e2fb7g",
    ],
)
def test_no_ethereum_address(text):
    assert "CRYPTO_ADDR" not in kinds(text)


@pytest.mark.skipif(openssl_keccak(b"") is None, reason="no Keccak-256 in this OpenSSL")
def test_generated_ethereum_addresses_and_a_changed_case():
    rng = random.Random("eth")
    for _ in range(40):
        address = eip55(bytes(rng.randrange(256) for _ in range(20)).hex())
        assert found(f"to {address}") == [("CRYPTO_ADDR", address)]
        i = rng.choice([i for i, c in enumerate(address) if c.isalpha() and i > 1])
        changed = address[:i] + address[i].swapcase() + address[i + 1 :]
        letters = [c for c in changed[2:] if c.isalpha()]
        single_case = all(c.islower() for c in letters) or all(c.isupper() for c in letters)  # then nothing is checked
        assert ("CRYPTO_ADDR" in kinds(changed)) == single_case, changed


# --- the Keccak-256 behind EIP-55


def test_keccak_256_of_known_inputs():
    assert _keccak256(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    assert _keccak256(b"abc").hex() == "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"


@pytest.mark.skipif(openssl_keccak(b"") is None, reason="no Keccak-256 in this OpenSSL")
def test_keccak_256_agrees_with_openssl_on_many_lengths():
    rng = random.Random(3)
    for n in [*range(0, 300), 1000]:  # across the block size of 136 bytes
        data = bytes(rng.randrange(256) for _ in range(n))
        assert _keccak256(data) == openssl_keccak(data), n


# --- where it is found

def test_the_span_is_the_address_only():
    text = "bitcoin:1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs?amount=0.01"
    (d,) = detect(text, level=2)
    assert text[d.start : d.end] == "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs"


def test_level_2_and_up_only():
    assert "CRYPTO_ADDR" in KINDS_BY_LEVEL[2] and "CRYPTO_ADDR" not in KINDS_BY_LEVEL[1]
    assert found("1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs", level=1) == []
    assert found("1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs", level=3) == [("CRYPTO_ADDR", "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs")]


def test_several_addresses_in_a_text():
    text = f"{BASE58_VECTORS[0]}, {SEGWIT_VALID[0]} and {ETH_CHECKSUMMED[0]}"
    assert [t for _, t in found(text)] == [BASE58_VECTORS[0], SEGWIT_VALID[0], ETH_CHECKSUMMED[0]]


# --- the work a checksum may take

def test_a_validator_is_asked_about_the_first_matches_only(monkeypatch):
    import re

    asked = []

    def no(value):
        asked.append(value)
        return False

    monkeypatch.setattr(patterns, "RULES", (Rule("rule:slow", "CRYPTO_ADDR", re.compile(r"\bx\d\b"), validator=no, budget=2),))
    got = [c.text for c in rule_candidates("x1 x2 x3 x4 x5")]
    assert asked == ["x1", "x2"]  # the first two are refused by the check; the rest are taken as they are
    assert got == ["x3", "x4", "x5"]
