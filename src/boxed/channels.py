"""API-key channels: send a masked prompt to OpenAI, Anthropic, DeepSeek or OpenRouter and restore the answer locally.

What a provider sends back is not trusted. A prompt, an answer, a key or any part of an error body never reaches an
exception text or a journal record: errors name the provider, the HTTP status and a word from a fixed list.
"""

import hashlib
import ipaddress
import json
import os
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass, replace
from decimal import ROUND_HALF_UP, Decimal

from . import __version__
from .config import ProjectConfig, to_detect_config
from .detect import KINDS_BY_LEVEL, detect
from .errors import UserError, number, one_of
from .journal import Journal, JournalEntry
from .keys import SERVICE
from .mask import MARKER_RE, MarkerMap, dictionary_kinds, mask_text, restore
from .policy import Decision, Policy, Recipient, categories_for, decide
from .vault import Vault


@dataclass(frozen=True)
class Provider:
    name: str
    base_url: str
    style: str  # "responses" | "messages" | "chat": the shape of the request and of the answer
    jurisdiction: str
    env_key: str
    default_account: str  # the recipient kind assumed when the person names none; the stricter one when unsure
    zero_retention: bool = False  # this request must go only to endpoints that keep nothing: ask() sets it for api-zero-retention


# Keyed by names written out: an error text names a provider, and tests/test_error_texts.py reads these keys as fixed words.
PROVIDERS: dict[str, Provider] = {
    "openai": Provider("openai", "https://api.openai.com/v1", "responses", "US", "OPENAI_API_KEY", "personal-private"),
    "anthropic": Provider("anthropic", "https://api.anthropic.com/v1", "messages", "US", "ANTHROPIC_API_KEY", "personal-private"),
    # these two may log or train on API traffic (DeepSeek's terms; OpenRouter passes on to a provider chosen per request)
    "deepseek": Provider("deepseek", "https://api.deepseek.com", "chat", "CN", "DEEPSEEK_API_KEY", "personal-training"),
    "openrouter": Provider("openrouter", "https://openrouter.ai/api/v1", "chat", "US", "OPENROUTER_API_KEY", "personal-training"),
}


@dataclass
class Answer:
    text: str
    model: str
    usage: dict[str, int]  # {"input": n, "output": m} as the provider reported them, and "cost_micro_usd" from OpenRouter; {} if none
    complete: bool = True  # False when the provider says the answer stopped short (token limit, interruption)


class ChannelError(UserError):
    """A failed call. The text is the provider, an HTTP status and a word from a fixed list, never a part of a body. Made by _fail
    only, at the place the words are known: tests/test_error_texts.py reads every call."""


_PATHS = {"responses": "/responses", "messages": "/messages", "chat": "/chat/completions"}
# OpenRouter's own request fields, as its public docs name them (provider routing, usage accounting). They sit here, once, so
# that a renamed field is one edit; they have not been checked against a live call.
_OPENROUTER_ROUTING = {"data_collection": "deny"}  # route only to providers that neither keep nor train on the data
_OPENROUTER_ZDR = {"zdr": True}  # and, for the api-zero-retention account, only to endpoints with zero data retention
_OPENROUTER_USAGE = {"include": True}  # ask for usage accounting; the docs now call it always on, so this is belt and braces
_OPENROUTER_COST_FIELD = "cost"  # in the answer's usage object: credits, and a credit is a US dollar
_USAGE_FIELDS = {
    "responses": ("input_tokens", "output_tokens"),
    "messages": ("input_tokens", "output_tokens"),
    "chat": ("prompt_tokens", "completion_tokens"),
}
# a key becomes a header value: visible ASCII only, so http.client never has to quote it in an error
_KEY_RE = re.compile(r"[\x21-\x7e]{1,1024}")
# a model name goes into the journal; the one the provider reports is used only when it looks like a name
_MODEL_RE = re.compile(r"[A-Za-z0-9~][A-Za-z0-9._:/@+~-]{0,127}")
_MAX_ERROR_BODY = 64 * 1024
_MAX_BODY = 10 * 1024 * 1024  # of an answer
_MAX_COST = 10**9  # millionths of a dollar, so $1,000 for one call; a figure beyond it is not believed (the dashboard agrees)
# the only words of an error body a message may name; everything else in a body stays out
_ERROR_WORDS = (
    "authentication_error", "invalid_api_key", "invalid_request_error", "permission_error", "not_found_error", "model_not_found",
    "rate_limit_error", "rate_limit_exceeded", "insufficient_quota", "billing_error", "context_length_exceeded", "request_too_large",
    "api_error", "server_error", "overloaded_error", "service_unavailable", "timeout_error",
)


def _valid_key(key: object) -> bool:
    return isinstance(key, str) and _KEY_RE.fullmatch(key) is not None


def _fail(provider: Provider, what: str) -> ChannelError:
    """The error of a call: the provider's name (a key of PROVIDERS) and `what`, fixed words that every caller writes out."""
    name = provider.name if provider.name in PROVIDERS else "provider"
    return ChannelError(f"{name}: {what}")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """urllib would follow a redirect with the key header still set; an API call is never redirected."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _request(provider: Provider, model: str, prompt: str, key: str) -> tuple[dict[str, str], dict]:
    """The authentication headers and the JSON body in the provider's style."""
    messages = [{"role": "user", "content": prompt}]
    if provider.style == "responses":
        # store false: the Responses API otherwise keeps the response for 30 days
        return {"Authorization": f"Bearer {key}"}, {"model": model, "input": prompt, "store": False}
    if provider.style == "messages":
        return {"x-api-key": key, "anthropic-version": "2023-06-01"}, {"model": model, "max_tokens": 4096, "messages": messages}
    body = {"model": model, "messages": messages}
    if provider.name == "openrouter":
        body["provider"] = _OPENROUTER_ROUTING | (_OPENROUTER_ZDR if provider.zero_retention else {})
        body["usage"] = dict(_OPENROUTER_USAGE)
    return {"Authorization": f"Bearer {key}"}, body


def _known_word(error: object) -> int | None:
    """The place in _ERROR_WORDS of the code or type of an error object, when it is one of the known words: the message takes the
    word from the table, never from the body."""
    if not isinstance(error, dict):
        return None
    for field in ("code", "type"):
        word = error.get(field)
        if isinstance(word, str) and word in _ERROR_WORDS:
            return _ERROR_WORDS.index(word)
    return None


def _error_word(raw: bytes) -> int | None:
    try:
        return _known_word(json.loads(raw)["error"])
    except (ValueError, RecursionError, KeyError, TypeError):
        return None


def _http_failure(provider: Provider, e: urllib.error.HTTPError) -> ChannelError:
    try:
        i = _error_word(e.read(_MAX_ERROR_BODY))
    except Exception:  # the connection died while the body was read
        i = None
    finally:
        e.close()
    return _fail(provider, f"HTTP {number(e.code) if type(e.code) is int else '?'}" + (f" ({_ERROR_WORDS[i]})" if i is not None else ""))


def _on_this_computer(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _opener(url: str) -> urllib.request.OpenerDirector:
    """Built per call: the proxy settings are those of the moment (HTTPS_PROXY is honoured). Never follows a redirect.

    An address on this computer is never handed to a proxy: urllib would do it when http_proxy is set and no_proxy says
    nothing, and the proxy would get the key and the prompt in the clear (and could not reach this computer anyway)."""
    handlers: list = [_NoRedirect]
    host = urllib.parse.urlsplit(url).hostname
    if host and _on_this_computer(host):
        handlers.append(urllib.request.ProxyHandler({}))
    return urllib.request.build_opener(*handlers)


def _fetch(provider: Provider, request: urllib.request.Request, timeout: float, deadline: float) -> bytes:
    """The body of a 2xx answer, read in pieces so that its size and the deadline are checked as it arrives."""
    with _opener(request.full_url).open(request, timeout=timeout) as response:
        chunks, size = [], 0
        while chunk := response.read1(65536):
            size += len(chunk)
            if size > _MAX_BODY:
                raise _fail(provider, "answer too large")
            if time.monotonic() > deadline:
                raise _fail(provider, "timed out")
            chunks.append(chunk)
    return b"".join(chunks)


def _attempt(provider: Provider, request: urllib.request.Request, timeout: float, deadline: float) -> tuple[bytes | None, ChannelError | None]:
    """(the body, None) or (None, why not). What the network raises becomes fixed words here, in the request's own thread; the
    error is made here and raised by the caller, outside every handler, so nothing is chained to it."""
    try:
        return _fetch(provider, request, timeout, deadline), None
    except ChannelError as e:
        failure = e
    except urllib.error.HTTPError as e:
        failure = _http_failure(provider, e)
    except TimeoutError:
        failure = _fail(provider, "timed out")
    except urllib.error.URLError as e:
        failure = _fail(provider, "timed out" if isinstance(e.reason, TimeoutError) else "network error")
    except Exception:  # http.client, ssl and socket errors: their texts can quote the request
        failure = _fail(provider, "network error")
    return None, failure


def _post(provider: Provider, url: str, data: bytes, headers: dict[str, str], timeout: float) -> bytes:
    """One deadline for connecting, waiting and reading. The request runs in a thread: the caller stops waiting for it when
    the deadline passes, and the thread stops reading an answer, and closes the connection, at its next read after that."""
    request = urllib.request.Request(
        url, data=data, method="POST", headers={"Content-Type": "application/json", "User-Agent": f"boxed/{__version__}", **headers}
    )
    deadline = time.monotonic() + timeout
    outcome: list[tuple[bytes | None, ChannelError | None]] = [(None, _fail(provider, "network error"))]  # replaced when it ends

    def run() -> None:
        outcome[0] = _attempt(provider, request, timeout, deadline)

    worker = threading.Thread(target=run, name="boxed-channel-request", daemon=True)
    worker.start()
    worker.join(timeout)
    body, failure = (None, _fail(provider, "timed out")) if worker.is_alive() else outcome[0]
    if body is None:
        raise failure  # here, outside every handler: nothing is chained to it
    return body


class _Malformed(ValueError):
    """The answer is not the shape its style promises."""


_REFUSED = "the model refused to answer"
_FILTERED = "the answer was filtered"


def _provider_error(provider: Provider, error: object) -> ChannelError:
    i = _known_word(error)
    return _fail(provider, "the provider reported an error" + (f" ({_ERROR_WORDS[i]})" if i is not None else ""))


def _objects(value: object) -> list[dict]:
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise _Malformed
    return value


def _string(part: dict) -> str:
    text = part.get("text")
    if not isinstance(text, str):
        raise _Malformed
    return text


def _extract(provider: Provider, data: object) -> tuple[str, object, object, bool]:
    """The answer text, the model the provider names, its usage object and whether the answer is whole, read in the shape
    of the provider's style. A body that is well formed but no answer (a failure, a refusal, a filter) raises a ChannelError.

    A stop reason this code does not know counts as "not whole"; a body that gives none counts as whole."""
    style = provider.style
    if not isinstance(data, dict):
        raise _Malformed
    if data.get("error") is not None or data.get("type") == "error":  # an error that came with HTTP 200
        raise _provider_error(provider, data.get("error"))
    if style == "responses":
        status = data.get("status")
        details = data.get("incomplete_details")
        if status == "failed":
            raise _provider_error(provider, None)
        if status == "incomplete" and isinstance(details, dict) and details.get("reason") == "content_filter":
            raise _fail(provider, _FILTERED)
        parts = [part for item in _objects(data.get("output")) for part in _objects(item.get("content") or [])]
        if any(part.get("type") == "refusal" for part in parts):
            raise _fail(provider, _REFUSED)
        text = "".join(_string(part) for part in parts if part.get("type") == "output_text")
        whole = status in (None, "completed")
    elif style == "messages":
        stop = data.get("stop_reason")
        if stop == "refusal":
            raise _fail(provider, _REFUSED)
        text = "".join(_string(part) for part in _objects(data.get("content")) if part.get("type") == "text")
        whole = stop in (None, "end_turn", "stop_sequence")
    else:
        choices = _objects(data.get("choices"))
        if not choices:
            raise _Malformed
        finish = choices[0].get("finish_reason")
        if finish == "error" or choices[0].get("error") is not None:
            raise _provider_error(provider, choices[0].get("error"))
        if finish == "content_filter":
            raise _fail(provider, _FILTERED)
        message = choices[0].get("message")
        if not isinstance(message, dict):
            raise _Malformed
        if message.get("refusal"):
            raise _fail(provider, _REFUSED)
        content = message.get("content")
        if content is not None and not isinstance(content, str):
            raise _Malformed
        text = content or ""
        whole = finish in (None, "stop")
    return text, data.get("model"), data.get("usage"), whole


def _cost_micro_usd(reported: object) -> int | None:
    """What the provider says the call cost, a JSON number of US dollars, as whole millionths of a dollar; None for anything
    that is not an amount boxed would believe. The number is read from its text: 0.000123 is 123 and not 122.99999999999999."""
    if type(reported) not in (int, float) or not 0 <= reported <= _MAX_COST / 1_000_000:  # also false for nan, inf and a bool
        return None
    return int((Decimal(repr(reported)) * 1_000_000).quantize(Decimal(1), rounding=ROUND_HALF_UP))


def _usage(provider: Provider, reported: object) -> dict[str, int]:
    """The token counts the provider reported and, for OpenRouter, the cost it reported, each only when it can be believed."""
    if not isinstance(reported, dict):
        return {}
    counts = {name: reported.get(field) for name, field in zip(("input", "output"), _USAGE_FIELDS[provider.style], strict=True)}
    usage = {name: n for name, n in counts.items() if type(n) is int and n >= 0}
    if provider.name == "openrouter" and (micro := _cost_micro_usd(reported.get(_OPENROUTER_COST_FIELD))) is not None:
        usage["cost_micro_usd"] = micro
    return usage


def _answer(provider: Provider, raw: bytes, requested: str, key: str) -> Answer:
    try:
        text, reported, usage, whole = _extract(provider, json.loads(raw))
        text.encode("utf-8")  # a lone surrogate would break hashing and printing later
    except ChannelError as e:  # before ValueError: a ChannelError is one
        failure = e
    except (ValueError, RecursionError):  # JSONDecodeError and UnicodeError are ValueErrors
        failure = _fail(provider, "malformed answer")
    else:
        # the name goes into the journal: only the requested model, perhaps with a version after it, and never the key
        named = isinstance(reported, str) and reported.startswith(requested) and key not in reported and _MODEL_RE.fullmatch(reported)
        return Answer(text, reported if named else requested, _usage(provider, usage), whole)
    raise failure  # outside every handler: nothing is chained to it


def call(provider: Provider, model: str, prompt: str, key: str, *, timeout: float = 120.0, base_url: str | None = None) -> Answer:
    """One request, no streaming. A failure is a ChannelError and nothing else.

    timeout is one deadline for the whole call: connecting, waiting and reading. An answer over 10 MiB is refused.
    base_url is for tests; the CLI never offers it.
    """
    if not _valid_key(key):
        raise _fail(provider, "invalid API key format")
    headers, body = _request(provider, model, prompt, key)
    try:
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
    except UnicodeEncodeError:  # a lone surrogate; the error text would quote it
        data = None
    if data is None:
        raise _fail(provider, "the request is not valid text")
    url = (base_url or provider.base_url).rstrip("/") + _PATHS[provider.style]
    return _answer(provider, _post(provider, url, data, headers, timeout), model, key)


class PolicyBlocked(Exception):
    """The policy forbids sending this text to this recipient. Nothing was masked or sent. A hint is a fixed sentence."""

    def __init__(self, decision: Decision, hint: str = "") -> None:
        # the reasons are in .decision; the text holds no value
        super().__init__(f"blocked by policy: {decision.verdict}" + (f": {hint}" if hint else ""))
        self.decision = decision


@dataclass
class AskResult:
    text: str  # the restored answer
    level: int
    verdict: str
    warnings: list[str]
    unknown: list[str]
    suspicious: list[str]
    model: str
    usage: dict[str, int]
    complete: bool = True  # False: the provider says the answer stopped short, so the CLI should say so


def _provider(name: str) -> Provider:
    try:
        return PROVIDERS[name]
    except KeyError:
        raise UserError(f"unknown provider, expected one of {one_of(PROVIDERS)}") from None


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()  # an answer is not trusted to be clean text


_KEY_REFUSAL = "the API key must be printable ASCII without spaces"
_RELAY_REFUSALS = {  # by provider; the refusal names the variable and never quotes the address
    name: f"BOXED_{name.upper()}_BASE_URL must be an https address (or http on this computer) without a login, query or fragment"
    for name in PROVIDERS
}
# The detector looks at level 4 as it does at 3, and a level 4 is not a masked prompt: it is the task and the table schema
# only, which boxed plan builds. ask refuses it, and a record never says 4 for a text that was masked at 3.
PLAN_LEVEL = max(KINDS_BY_LEVEL)
_PLAN_REFUSAL = f"level {PLAN_LEVEL} sends the task and the table schema only: use boxed plan, or ask at a level from 0 to {PLAN_LEVEL - 1}"
_PLAN_HINT = f"the policy asks for level {PLAN_LEVEL}, which sends the task and the table schema only: use boxed plan"
_HOST_RE = re.compile(r"[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*")


def _is_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return _HOST_RE.fullmatch(host) is not None
    return True


def _relay(spec: Provider) -> str | None:
    """The address in BOXED_<PROVIDER>_BASE_URL, for a relay the person runs or trusts, or None when it is not set. The key
    and the masked prompt go there instead of to the provider, so it must be https, or http to this computer; a login, a query
    or a fragment would end up in logs and error texts. The refusal never quotes the address."""
    name = f"BOXED_{spec.name.upper()}_BASE_URL"
    value = os.environ.get(name, "").strip()
    if not value:
        return None
    try:
        parts = urllib.parse.urlsplit(value)
        host, _ = parts.hostname, parts.port  # reading the port raises ValueError for one that is not a number
    except ValueError:  # that, or a broken bracket
        host = None
    ok = (
        re.fullmatch(r"[\x21-\x7e]+", value) is not None  # visible ASCII: no space, no line break, no letters of another script
        and "?" not in value  # not even an empty query or fragment: the path would turn into /v1?/responses
        and "#" not in value
        and host is not None
        and _is_address(host)
        and (parts.username, parts.password) == (None, None)
        and (parts.scheme == "https" or (parts.scheme == "http" and _on_this_computer(host)))
    )
    if not ok:
        raise UserError(_RELAY_REFUSALS[spec.name])
    return value


def _this_prompt(markers: MarkerMap, masked: str) -> MarkerMap:
    """The markers of the scope whose placeholders occur in this masked prompt. An answer gets back only what it was shown:
    the scope holds the placeholders of earlier prompts too, and text from the network must not be able to ask for them."""
    shown = {m.group(0) for m in MARKER_RE.finditer(masked)}
    items = [list(item) for item in markers.items() if item[0] in shown]
    return MarkerMap.from_json(json.dumps({"version": 1, "items": items}))


def _check_arguments(text: str, model: str, key: str, level: int | None, account: str | None) -> None:
    """Refuse what could never be sent, before anything is recorded. The texts are fixed: none quotes an argument."""
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:  # a lone surrogate
        raise UserError("the text is not valid Unicode") from None
    if account == "local":  # the policy lets everything go to a local recipient; an API call always leaves the computer
        raise UserError("a remote API is never a local recipient")
    if not isinstance(model, str) or not _MODEL_RE.fullmatch(model):
        raise UserError("bad model name")
    if not _valid_key(key):
        raise UserError(_KEY_REFUSAL)
    if level is not None and (type(level) is not int or level not in KINDS_BY_LEVEL):
        raise UserError(f"level must be {min(KINDS_BY_LEVEL)}-{PLAN_LEVEL - 1}")


def ask(
    text: str,
    *,
    provider: str,
    model: str,
    key: str,
    scope: str,
    vault: Vault,
    journal: Journal,
    config: ProjectConfig,
    account: str | None = None,
    level: int | None = None,
    categories: Iterable[str] = (),
    transport: Callable[[Provider, str, str, str], Answer] = call,
) -> AskResult:
    """Policy, then masking, then the journal, then the request, then the journal and the restore: each before the next.

    Raises PolicyBlocked (nothing masked or sent), ChannelError (the request failed, or the answer was an error, a refusal or
    could not be restored: all journaled as "error") or ValueError for an argument that could never be sent, such as the
    account "local". A journal or vault that cannot be written raises its own error before anything leaves; one that cannot
    write "received" or "error" raises its error instead of handing over the answer or the channel error.

    The answer gets back only the placeholders of this prompt, not those of other prompts in the scope.

    strategy, hr and health have no detector, and finance only finds the amounts of level 3: `categories` names the ones the
    caller knows the text belongs to, and they count for the policy next to what the detectors raise. A name the policy does
    not know is a PolicyError.

    Level 4 is a plan (the task and the table schema, boxed plan), not a masked prompt: a level 4 from the argument or from
    config.level is a ValueError, and a policy decision that needs level 4 is a PolicyBlocked whose text says to use boxed
    plan. The most a record of ask says is level 3.

    BOXED_<PROVIDER>_BASE_URL, when set, replaces the provider's address (a relay: https, or http to this computer, else a
    ValueError before anything is recorded); the "sent" record is then noted "relay". The transport gets a Provider with that
    address, and with zero_retention set when the account is api-zero-retention.
    """
    spec = _provider(provider)
    _check_arguments(text, model, key, level, account)
    asked = config.level if level is None else level
    if asked >= PLAN_LEVEL:
        raise UserError(_PLAN_REFUSAL)
    relay = _relay(spec)
    recipient = Recipient(spec.name, account or spec.default_account, spec.jurisdiction)
    spec = replace(spec, base_url=relay or spec.base_url, zero_retention=recipient.kind == "api-zero-retention")
    detect_config = to_detect_config(config)
    found = detect(text, level=max(KINDS_BY_LEVEL), config=detect_config)  # the widest look decides, whatever level is asked
    named = categories_for({d.kind for d in found}, dictionary_kinds(config)) | set(categories)
    decision = decide(named, recipient, Policy.from_config(config.policy))

    def record(status: str, at_level: int, counts: dict[str, int], payload: str, **more) -> None:
        journal.append(
            JournalEntry(
                channel="api",
                provider=spec.name,
                account_type=recipient.kind,
                level=at_level,
                markers_by_kind=counts,
                status=status,
                payload_sha256=_sha(payload),
                coverage="full",
                scope=scope,
                versions={"boxed": __version__},
                **more,
            )
        )

    needs_plan = decision.verdict == "masked" and (decision.min_level or 0) >= PLAN_LEVEL
    if decision.verdict in ("deny", "local-only") or needs_plan:
        note = f"policy masked at level {PLAN_LEVEL}: use boxed plan" if needs_plan else f"policy {decision.verdict}"
        record("blocked", asked, dict(Counter(d.kind for d in found)), "", note=note)  # no payload exists
        raise PolicyBlocked(decision, _PLAN_HINT if needs_plan else "")
    used = max(asked, decision.min_level or 0)
    with vault.transaction(scope) as markers:  # saved on leaving; the lock is not held while the request is out
        masked, counts = mask_text(text, markers, level=used, config=detect_config)
    record("sent", used, counts, masked, model=model, note="relay" if relay else "")  # nothing leaves before this record is written
    failure = None
    try:
        answer = transport(spec, model, masked, key)
    except ChannelError as e:
        failure = e
    except Exception:  # a transport that is not ours: its error text may quote the prompt
        failure = _fail(spec, "request failed")
    else:
        try:
            result = restore(answer.text, _this_prompt(markers, masked), dictionary_kinds(config))
        except Exception:  # text from the network can break the reader, for one with a number too long to read
            failure = _fail(spec, "the answer cannot be restored")
    if failure is not None:  # raised outside the handlers, so nothing is chained to it
        record("error", used, {}, masked, model=model, note=str(failure))  # "sent" counted the kinds: once is enough
        raise failure
    note = f"restored={result.restored} unknown={len(result.unknown)} suspicious={len(result.suspicious)}"
    record("received", -1, {}, answer.text, model=answer.model, usage=answer.usage, note=note)  # before the answer is handed over
    return AskResult(
        result.text, used, decision.verdict, decision.warnings, result.unknown, result.suspicious, answer.model, answer.usage, answer.complete
    )


def _keychain_name(provider: str) -> tuple[Provider, str]:
    spec = _provider(provider)
    return spec, f"api-key:{spec.name}"


def _find_key(provider: str) -> tuple[str | None, str | None]:
    """The key and where it came from: the keychain (service boxed.si, user api-key:<provider>), else the provider's
    environment variable. A keychain that cannot be read counts as holding no key, so a server without one can still use
    the variable."""
    import keyring

    spec, name = _keychain_name(provider)
    try:
        stored = (keyring.get_password(SERVICE, name) or "").strip()
    except Exception:  # no backend, a locked keychain or a backend's own error: the variable is the way left
        stored = ""
    if stored:
        return stored, "keychain"
    value = os.environ.get(spec.env_key, "").strip()
    return (value, "environment") if value else (None, None)


def api_key(provider: str) -> str | None:
    """The key from the keychain, else from the provider's environment variable; None when there is neither."""
    return _find_key(provider)[0]


def key_source(provider: str) -> str | None:
    """Where api_key() finds the key: "keychain", "environment" or None. It never returns the key."""
    return _find_key(provider)[1]


def set_api_key(provider: str, key: str) -> None:
    import keyring

    spec, name = _keychain_name(provider)
    key = key.strip()
    if not _valid_key(key):
        raise UserError(_KEY_REFUSAL)
    try:
        keyring.set_password(SERVICE, name, key)
    except Exception:  # a backend's error text may quote the key
        pass
    else:
        return
    raise _fail(spec, "cannot store the key in the keychain")


def delete_api_key(provider: str) -> None:
    """Remove the keychain entry; the environment variable is not ours to touch. Nothing to remove is not an error."""
    import keyring

    spec, name = _keychain_name(provider)
    try:
        if keyring.get_password(SERVICE, name) is not None:
            keyring.delete_password(SERVICE, name)
    except Exception:
        pass
    else:
        return
    raise _fail(spec, "cannot remove the key from the keychain")
