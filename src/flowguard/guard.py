"""Guard: the object you put between an agent and its tools."""

from __future__ import annotations

import dataclasses
import functools
import hashlib
import hmac
import inspect
import json
import os
import re
import threading
from collections.abc import Callable, Iterable, Iterator, Mapping
from email.utils import getaddresses
from pathlib import Path
from typing import Any

from .audit import AuditLog
from .decision import Decision, Finding, FlowBlocked
from .expand import expand
from .labels import Level
from .policy import Policy
from .taint import TaintRegistry

_MAX_WALK_DEPTH = 32
_MAX_JSON_PARSE_CHARS = 1_000_000
_MAX_TRACKED_DESTINATIONS = 1024
_MIN_STITCH_WINDOW = 256
_STITCH_EXPANSION = 8  # an encoded secret can be up to ~8x its length (hex, char codes, HTML entities)


_HOST_CHARS = re.compile(r"[A-Za-z0-9._-]+")
_BARE_HOST = re.compile(r"[A-Za-z0-9._-]+(?::[0-9]*)?(?:[/?#].*)?", re.DOTALL)
_EMAIL_ALLOWED = re.compile(r"[A-Za-z0-9._%+'@,; <>\"-]*")


def _clean_host(host: str) -> str:
    if host.endswith("."):  # "example.com." is the same DNS name as "example.com"
        host = host[:-1]
    return host.lower() if _HOST_CHARS.fullmatch(host) and host and not host.startswith(".") else ""


def hostname(url: str) -> str:
    """Destination helper: ``"https://api.example.com/v1"`` -> ``"api.example.com"``.

    URL parsers disagree about odd input (``https://evil.test\\@trusted.example`` is
    ``trusted.example`` to one library and ``evil.test`` to another), so a lenient parser here
    would let a model pick a URL that the policy reads as trusted while the HTTP client connects
    elsewhere. This one is strict instead: anything ambiguous returns ``""`` (an unknown
    destination, which may only receive PUBLIC data). That covers backslashes, whitespace and
    control characters, credentials in the URL (``user@host``), percent-escapes or non-ASCII in the
    host (pass IDNs as punycode), a malformed port, and scheme-less forms it cannot read.
    """
    text = str(url)
    if any(ord(c) <= 32 or ord(c) >= 127 or c == "\\" for c in text):
        return ""
    if text.count("://") == 1:
        rest = text.split("://", 1)[1]
    elif "://" in text:
        return ""  # more than one "://": which one a client treats as the delimiter is ambiguous
    elif text.startswith("//"):
        rest = text[2:]
    elif _BARE_HOST.fullmatch(text):
        rest = text
    else:
        return ""
    authority = re.split(r"[/?#]", rest, maxsplit=1)[0]
    if not authority or "@" in authority:
        return ""
    if authority.startswith("["):  # IPv6 literal
        host, _, tail = authority[1:].partition("]")
        port = tail[1:] if tail.startswith(":") else ("" if not tail else "!")
        if not re.fullmatch(r"[0-9A-Fa-f:.]+", host):
            return ""
    else:
        host, _, port = authority.partition(":") if authority.count(":") <= 1 else (authority, "", "!")
    if port == "!" or (port and not (port.isdigit() and int(port) <= 65535)):
        return ""
    return host.lower() if authority.startswith("[") else _clean_host(host)


def email_domains(recipients: str | Iterable[str]) -> list[str]:
    """Destination helper for email: the domain of *every* recipient.

    A ``to`` string may carry several addresses (``a@evil.test, b@trusted.example``) and a mail
    library sends to all of them, so the destination is the whole list; the strictest domain
    decides (see :meth:`Guard.sink`). Unreadable input yields ``[""]`` (unknown destination).
    """
    items = [recipients] if isinstance(recipients, str) else [str(r) for r in recipients]
    domains: list[str] = []
    for item in items:
        if not _EMAIL_ALLOWED.fullmatch(item):
            return [""]
        addresses = [addr for _, addr in getaddresses([item.replace(";", ",")]) if addr]
        if not addresses:
            return [""]
        for addr in addresses:
            local, sep, domain = addr.rpartition("@")
            domains.append(_clean_host(domain) if sep and local and "@" not in local else "")
    return domains or [""]


def email_domain(address: str) -> str:
    """Destination helper for a single address. Several addresses, or anything ambiguous, give
    ``""`` (an unknown destination); use :func:`email_domains` for a recipient list."""
    domains = email_domains(address)
    return domains[0] if len(domains) == 1 else ""


def _worth_auditing(value: Any) -> bool:
    """Only leaf, non-trivial values are worth reporting as unlabeled: a nested container's
    own fields are visited (and can be reported) separately, and very short values are noise."""
    if isinstance(value, str):
        return len(value.strip()) >= 3
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _first_visit(obj: Any, seen: set[int]) -> bool:
    """True the first time a container is met. Skipping repeats makes traversal linear even
    for cyclic or heavily shared structures (ORM back-references, crafted payloads)."""
    if id(obj) in seen:
        return False
    seen.add(id(obj))
    return True


def iter_texts(obj: Any, depth: int = 0, *, keys: bool = True, _seen: set[int] | None = None) -> Iterator[str]:
    """Flatten an arbitrary tool argument into the strings it carries.

    Mapping keys are included by default because they are a channel too;
    ``keys=False`` yields values only (used to stitch consecutive sends together
    without the field names getting in between the pieces).
    """
    if obj is None or isinstance(obj, bool):
        return
    if isinstance(obj, str):
        yield obj
        return
    if isinstance(obj, (bytes, bytearray)):
        yield bytes(obj).decode("utf-8", errors="ignore")
        return
    if isinstance(obj, (int, float)):
        yield str(obj)
        return
    seen = set() if _seen is None else _seen
    is_container = isinstance(obj, (Mapping, list, tuple, set, frozenset)) or (
        dataclasses.is_dataclass(obj) and not isinstance(obj, type)
    )
    if is_container and not _first_visit(obj, seen):
        return
    if depth >= _MAX_WALK_DEPTH:
        yield str(obj)  # too deep to walk: stringify rather than skip
    elif isinstance(obj, Mapping):
        for key, value in obj.items():
            if keys:
                yield from iter_texts(key, depth + 1, keys=keys, _seen=seen)
            yield from iter_texts(value, depth + 1, keys=keys, _seen=seen)
    elif isinstance(obj, (list, tuple, set, frozenset)):
        for item in obj:
            yield from iter_texts(item, depth + 1, keys=keys, _seen=seen)
    elif is_container:
        for f in dataclasses.fields(obj):
            yield from iter_texts(getattr(obj, f.name), depth + 1, keys=keys, _seen=seen)
    else:
        yield str(obj)


def _kwargs_for(fn: Callable[..., Any], arguments: dict[str, Any]) -> dict[str, Any]:
    params = inspect.signature(fn).parameters
    if any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values()):
        return arguments
    return {k: v for k, v in arguments.items() if k in params}


class Guard:
    """Tracks sensitive values seen by the agent and vets every outbound payload.

    Workflow: mark data-reading tools as *sources* (:meth:`source` /
    :meth:`observe`) and data-sending tools as *sinks* (:meth:`sink` /
    :meth:`check`). A Guard instance is one session: create one per agent run,
    or call :meth:`reset` between runs.

    `mode="monitor"` logs would-be violations but lets everything through, for
    rolling FlowGuard out against a live agent before enforcing.
    """

    def __init__(
        self,
        policy: Policy | None = None,
        *,
        mode: str = "enforce",
        audit_path: str | Path | None = None,
        max_scan_chars: int = 2_000_000,
        oversize: str = "scan-raw",
        buffer_chars: int = 20_000,
        require_approval_above: Any | None = None,
        approve: Callable[[str, Any, tuple[Finding, ...]], bool] | None = None,
        audit_unlabeled: bool = False,
        cross_destination_fragments: bool = False,
    ):
        if mode not in ("enforce", "monitor"):
            raise ValueError("mode must be 'enforce' or 'monitor'")
        if oversize not in ("scan-raw", "block"):
            raise ValueError("oversize must be 'scan-raw' or 'block'")
        if (require_approval_above is None) != (approve is None):
            raise ValueError("require_approval_above and approve must be set together")
        self.policy = policy or Policy.default()
        self.mode = mode
        self.max_scan_chars = max_scan_chars
        self.oversize = oversize
        self.buffer_chars = buffer_chars
        self.audit = AuditLog(audit_path)
        self._key = os.urandom(16)
        self._lock = threading.RLock()
        self.registry = TaintRegistry(self.policy.min_value_length, self._fingerprint)
        self._approve = approve
        # `scan()` returns findings with level > `above`; PUBLIC has nothing below it, so
        # `require_approval_above="PUBLIC"` still uses PUBLIC as `above` here, meaning it gates
        # anything tracked ABOVE public (i.e. everything except data explicitly labeled PUBLIC,
        # for which approval would be pointless) -- the one level this can never gate is PUBLIC
        # itself, since nothing sits below it to serve as a strict threshold.
        self._approval_above = (
            Level(max(int(Level.PUBLIC), int(Level.parse(require_approval_above)) - 1))
            if require_approval_above is not None
            else None
        )
        # Per destination: recent outbound values per argument (to stitch consecutive
        # fragments without constant arguments such as a URL landing between them),
        # and how much of each tracked value has already been disclosed there.
        # The model chooses destination names, so both maps are capped (oldest evicted).
        self._buffers: dict[str, dict[str, str]] = {}
        self._coverage: dict[str, dict[str, int]] = {}
        # field name -> times seen with no label of its own AND no inherited one, in observe().
        # A diagnostic, not an enforcement mechanism: FlowGuard is a deny-list of known-sensitive
        # values, so this exists to help find field names worth adding to the policy, not to
        # detect sensitivity on its own. Off by default (a live registry can have many distinct
        # field names, and this is only useful while reviewing coverage).
        self.unlabeled_fields: dict[str, int] | None = {} if audit_unlabeled else None
        # Off by default: fragment stitching/coverage is normally tracked per destination, so
        # splitting a secret across two DIFFERENT destinations defeats it (each holds only part).
        # Turning this on tracks it in one shared bucket instead, closing that gap at the cost of
        # a real false-positive risk of its own -- unrelated data legitimately sent to several
        # destinations can now accumulate together. See docs/THREAT_MODEL.md.
        self.cross_destination_fragments = cross_destination_fragments

    # -- session state -------------------------------------------------

    def _fingerprint(self, value: str) -> str:
        return hmac.new(self._key, value.encode(), hashlib.sha256).hexdigest()[:12]

    def reset(self) -> None:
        """Forget every tainted value and outbound history (start a new session)."""
        with self._lock:
            self.registry.clear()
            self._buffers.clear()
            self._coverage.clear()

    def reset_history(self) -> None:
        """Forget what has been sent so far but keep the tainted values, e.g. between
        independent conversations that share one set of labels."""
        with self._lock:
            self._buffers.clear()
            self._coverage.clear()

    # -- sources -------------------------------------------------------

    def taint(self, value: Any, level: Any, *, origin: str = "manual") -> None:
        """Explicitly mark a value (or every string/number inside it) as `level`."""
        with self._lock:
            self._walk(value, origin, Level.parse(level), 0, set())

    def observe(self, data: Any, *, source: str = "unknown") -> Any:
        """Register the sensitive parts of a tool result, then return it unchanged.

        Values are found through the policy's field names (``{"ssn": ...}``) and
        pattern detectors (SSNs, card numbers, keys, ...), including inside
        JSON strings.
        """
        with self._lock:
            self._walk(data, source, None, 0, set())
        return data

    def unlabeled_report(self, limit: int = 20) -> str:
        """Human-readable summary of `unlabeled_fields` (requires ``audit_unlabeled=True``),
        most-seen field first: field names worth reviewing for `Policy.fields`. This is a
        starting point for a human to review, not a verdict -- a name appearing often is not
        proof it is sensitive, and one appearing rarely is not proof it is safe."""
        if self.unlabeled_fields is None:
            return "unlabeled_fields tracking is off (construct Guard(audit_unlabeled=True))."
        if not self.unlabeled_fields:
            return "No unlabeled fields observed yet."
        ranked = sorted(self.unlabeled_fields.items(), key=lambda kv: (-kv[1], kv[0]))
        lines = [f"  {name!r}: seen {count} time(s)" for name, count in ranked[:limit]]
        if len(ranked) > limit:
            lines.append(f"  ... and {len(ranked) - limit} more field name(s)")
        return "Unlabeled fields (not in Policy.fields, no inherited label):\n" + "\n".join(lines)

    def _register(self, text: str, level: Level, origin: str, kind: str) -> None:
        self.registry.add(text, level, origin, kind)

    def _walk(self, node: Any, origin: str, inherited: Level | None, depth: int, seen: set[int]) -> None:
        if node is None or isinstance(node, bool) or depth > _MAX_WALK_DEPTH:
            return
        if not isinstance(node, (str, bytes, bytearray, int, float)) and not _first_visit(node, seen):
            return
        if isinstance(node, Mapping):
            for key, value in node.items():
                own = self.policy.field_level(key)
                level = max(filter(None, (inherited, own)), default=None)
                if self.unlabeled_fields is not None and level is None and _worth_auditing(value):
                    name = str(key)
                    self.unlabeled_fields[name] = self.unlabeled_fields.get(name, 0) + 1
                self._walk(value, f"{origin}.{key}" if own else origin, level, depth + 1, seen)
        elif isinstance(node, (list, tuple, set, frozenset)):
            for item in node:
                self._walk(item, origin, inherited, depth + 1, seen)
        elif isinstance(node, (bytes, bytearray)):
            self._walk(bytes(node).decode("utf-8", errors="ignore"), origin, inherited, depth + 1, seen)
        elif isinstance(node, (int, float)):
            if inherited is not None:
                for text in self._number_forms(node):
                    self._register(text, inherited, origin, "field")
        elif isinstance(node, str):
            self._walk_string(node, origin, inherited, depth, seen)
        elif dataclasses.is_dataclass(node) and not isinstance(node, type):
            self._walk(dataclasses.asdict(node), origin, inherited, depth + 1, seen)
        elif hasattr(node, "model_dump"):
            self._walk(node.model_dump(), origin, inherited, depth + 1, seen)
        elif hasattr(node, "__dict__"):
            self._walk(vars(node), origin, inherited, depth + 1, seen)

    def _walk_string(self, text: str, origin: str, inherited: Level | None, depth: int, seen: set[int]) -> None:
        if inherited is not None:
            self._register(text, inherited, origin, "field")
        stripped = text.lstrip()
        if stripped[:1] in ("{", "[") and len(text) <= _MAX_JSON_PARSE_CHARS:
            try:
                parsed = json.loads(text)
            except ValueError:
                parsed = None
            if parsed is not None:
                self._walk(parsed, origin, inherited, depth + 1, seen)
        for rule in self.policy.patterns:
            for value in rule.find(text):
                self._register(value, rule.level, origin, f"pattern:{rule.name}")

    @staticmethod
    def _number_forms(value: int | float) -> list[str]:
        forms = [str(value)]
        if isinstance(value, float) and value.is_integer():
            value = int(value)
            forms.append(str(value))
        if isinstance(value, int):
            forms.append(f"{value:,}")
        return forms

    # -- sinks ---------------------------------------------------------

    def check(self, destination: Any, payload: Any, *, tool: str = "") -> Decision:
        """Decide whether `payload` may be sent to `destination`. Always audited."""
        with self._lock:
            dest = str(destination)
            key = dest.strip().lower()
            frag_key = self._frag_key(key)
            dest_level = self.policy.destination_level(dest)
            joined_nl = "\n".join(iter_texts(payload))
            parts = self._parts(payload)
            variants = self._variants(joined_nl)

            findings: list[Finding] = []
            coverage_updates: dict[str, int] = {}
            if dest_level < max(Level):
                findings, coverage_updates = self._scan(variants, parts, frag_key, dest_level)
                if len(joined_nl) > self.max_scan_chars and self.oversize == "block":
                    findings.append(
                        Finding(max(Level), "guard", "payload-too-large", fingerprint="oversize")
                    )

            violation = bool(findings)
            needs_approval, approval_denied = False, False
            if not violation and self._approval_above is not None:
                approval_findings = self.registry.scan(variants, self._approval_above)
                if approval_findings:
                    needs_approval = True
                    assert self._approve is not None  # invariant: set together in __init__
                    try:
                        approved = bool(self._approve(dest, payload, tuple(approval_findings)))
                    except Exception:  # noqa: BLE001 -- a broken callback must fail closed, not open
                        approved = False
                    if not approved:
                        findings = approval_findings
                        violation = approval_denied = True

            allowed = not violation or self.mode == "monitor"
            reason = self._reason(dest, dest_level, findings, allowed, violation, approval_denied)
            decision = Decision(
                allowed=allowed,
                violation=violation,
                destination=dest,
                destination_level=dest_level,
                findings=tuple(findings),
                reason=reason,
                tool=tool,
                mode=self.mode,
                needs_approval=needs_approval,
            )
            if allowed:  # only what actually left counts as disclosed
                self._evict_for(self._buffers, frag_key)
                history = self._buffers.setdefault(frag_key, {})
                for name, values in parts.items():
                    history[name] = (history.get(name, "") + values)[-self.buffer_chars :]
                if coverage_updates:
                    self._evict_for(self._coverage, frag_key)
                    self._coverage.setdefault(frag_key, {}).update(coverage_updates)
            self.audit.record(
                {
                    "tool": tool,
                    "destination": dest,
                    "destination_level": dest_level.name,
                    "allowed": allowed,
                    "violation": violation,
                    "mode": self.mode,
                    "payload_chars": len(joined_nl),
                    "payload_fp": self._fingerprint(joined_nl),
                    "findings": [f.as_dict() for f in findings],
                    "reason": reason,
                }
            )
            return decision

    def enforce(self, destination: Any, payload: Any, *, tool: str = "") -> Decision:
        """Like :meth:`check` but raises :class:`FlowBlocked` when the flow is denied."""
        decision = self.check(destination, payload, tool=tool)
        if decision.blocked:
            raise FlowBlocked(decision)
        return decision

    def _variants(self, text: str) -> list[tuple[str, str]]:
        if len(text) > self.max_scan_chars:
            return [(text, "")]  # too large to decode: verbatim scan only
        return expand(text)

    def _stitch_window(self) -> int:
        """How much recent output can still be part of a secret that ends in this send.
        Decoding the whole history on every call would make each check slower than the last."""
        return min(self.buffer_chars, max(_MIN_STITCH_WINDOW, self.registry.max_length * _STITCH_EXPANSION))

    _GLOBAL_FRAGMENT_KEY = "*"  # used for _buffers/_coverage instead of a real destination key

    def _frag_key(self, key: str) -> str:
        """The key used to look up/store fragment-stitching and coverage state: the destination
        itself normally, or one shared bucket when `cross_destination_fragments` is on."""
        return self._GLOBAL_FRAGMENT_KEY if self.cross_destination_fragments else key

    def _evict_for(self, state: dict, key: str) -> None:
        """Make room for `key` if `state` is at capacity, evicting the destination with the
        LEAST fragment-disclosure progress (not simply the oldest).

        Destination names are chosen by whatever the model puts in a tool call, so an attacker
        who cannot complete a leak directly could instead flood many disposable destination names
        to evict the *real* target's in-progress fragment/coverage state and make FlowGuard forget
        how much of a secret has already been sent there. Evicting the least-progressed entry
        defeats that: decoys the attacker didn't bother partially matching are removed first, and
        an attack already close to completion outlives a flood of unrelated destination names.
        Progress is approximated by the most bits any tracked value has accumulated there.
        """
        if key in state or len(state) < _MAX_TRACKED_DESTINATIONS:
            return

        def progress(candidate: str) -> int:
            # Coverage bits are the strongest signal (a value is measurably being disclosed
            # there); buffered content length is a weaker fallback so a destination mid-way
            # through *consecutive* stitching -- e.g. an all-digit secret, which does not use
            # the coverage path at all, see TaintRegistry.add -- is not treated as brand new.
            cov = self._coverage.get(candidate)
            cov_bits = max((v.bit_count() for v in cov.values()), default=0) if cov else 0
            buf = self._buffers.get(candidate)
            buf_len = max((len(v) for v in buf.values()), default=0) if buf else 0
            return cov_bits * 10_000 + min(buf_len, 9_999)

        del state[min(state, key=progress)]

    @staticmethod
    def _parts(payload: Any) -> dict[str, str]:
        """Values-only text per top-level argument (a bare payload is one part)."""
        if isinstance(payload, Mapping):
            return {str(k): "".join(iter_texts(v, keys=False)) for k, v in payload.items()}
        return {"": "".join(iter_texts(payload, keys=False))}

    def _scan(
        self, variants: list[tuple[str, str]], parts: dict[str, str], key: str, dest_level: Level
    ) -> tuple[list[Finding], dict[str, int]]:
        """Three passes, cheapest first, stopping at the first that finds something:
        1. the payload itself, including every decoded variant;
        2. earlier sends to this destination stitched to this one, argument by argument
           (consecutive fragments);
        3. cumulative coverage (fragments in any order, wrapped in any noise).
        """
        found = self._scan_variants(variants, dest_level, fragmented=False)
        if found:
            return found, {}
        history = self._buffers.get(key, {})
        for name, values in parts.items():
            prior = history.get(name, "")[-self._stitch_window() :]
            if prior and values:
                found = self._scan_variants(self._variants(prior + values), dest_level, fragmented=True)
                if found:
                    return found, {}
        return self.registry.coverage(
            variants, dest_level, self._coverage.get(key, {}), self.policy.fragment_threshold_for
        )

    def _scan_variants(
        self, variants: list[tuple[str, str]], dest_level: Level, *, fragmented: bool
    ) -> list[Finding]:
        found = {f.fingerprint: f for f in self.registry.scan(variants, dest_level, fragmented=fragmented)}
        for text, via in variants:
            for rule in self.policy.patterns:
                if rule.level <= dest_level:
                    continue
                for value in rule.find(text):
                    fp = self._fingerprint(value.strip())
                    if fp not in found:
                        found[fp] = Finding(
                            level=rule.level,
                            origin="content",
                            kind=f"pattern:{rule.name}",
                            via=via,
                            fingerprint=fp,
                            fragmented=fragmented,
                        )
        return list(found.values())

    @staticmethod
    def _reason(
        dest: str, dest_level: Level, findings: list[Finding], allowed: bool, violation: bool,
        approval_denied: bool = False,
    ) -> str:
        if not violation:
            return f"ALLOW: nothing above {dest_level.name} found for destination '{dest}'"
        parts = []
        for f in findings[:5]:
            part = f"{f.level.name} data from {f.origin}"
            if f.via:
                part += f" hidden via {f.via}"
            if f.fragmented:
                part += " (fragmented across sends)"
            parts.append(part)
        more = f" and {len(findings) - 5} more" if len(findings) > 5 else ""
        verdict = "BLOCK" if allowed is False else "MONITOR (would block)"
        if approval_denied:
            return (
                f"{verdict} (approval denied): destination '{dest}' is allowed up to "
                f"{dest_level.name} by policy, but the payload contains {'; '.join(parts)}{more} "
                "and a human reviewer did not approve it"
            )
        return (
            f"{verdict}: destination '{dest}' accepts up to {dest_level.name} but the payload "
            f"contains {'; '.join(parts)}{more}"
        )

    # -- decorators ----------------------------------------------------

    def source(self, name: str | None = None) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Decorator: everything the wrapped tool returns is run through :meth:`observe`."""

        def decorate(fn: Callable[..., Any]) -> Callable[..., Any]:
            label = name or fn.__qualname__
            if inspect.iscoroutinefunction(fn):

                @functools.wraps(fn)
                async def awrapper(*args: Any, **kwargs: Any) -> Any:
                    return self.observe(await fn(*args, **kwargs), source=label)

                return awrapper

            @functools.wraps(fn)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                return self.observe(fn(*args, **kwargs), source=label)

            return wrapper

        return decorate

    def sink(
        self,
        destination: str | Callable[..., Any],
        *,
        args: Iterable[str] | None = None,
        tool: str | None = None,
        on_block: str = "raise",
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Decorator: vet the wrapped tool's arguments before it runs.

        `destination` is a fixed key, or a callable that receives the tool's
        arguments (only the ones it names, unless it takes ``**kwargs``) and
        returns the destination key or a list of keys, e.g.
        ``lambda url: hostname(url)``. `args` limits which arguments are
        inspected (default: all). With ``on_block="raise"`` a denied call
        raises :class:`FlowBlocked`; with ``"return"`` it returns a short
        denial string instead.
        """
        if on_block not in ("raise", "return"):
            raise ValueError("on_block must be 'raise' or 'return'")
        inspected = set(args) if args is not None else None

        def decorate(fn: Callable[..., Any]) -> Callable[..., Any]:
            signature = inspect.signature(fn)
            label = tool or fn.__qualname__

            def gate(call_args: tuple, call_kwargs: dict) -> str | None:
                bound = signature.bind(*call_args, **call_kwargs)
                bound.apply_defaults()
                arguments = dict(bound.arguments)
                if callable(destination):
                    dests = destination(**_kwargs_for(destination, arguments))
                else:
                    dests = destination
                dest_list = [dests] if isinstance(dests, str) or not isinstance(dests, Iterable) else list(dests)
                payload = {k: v for k, v in arguments.items() if inspected is None or k in inspected}
                for dest in dest_list or [""]:
                    decision = self.check(dest, payload, tool=label)
                    if decision.blocked:
                        if on_block == "raise":
                            raise FlowBlocked(decision)
                        return decision.public_reason
                return None

            if inspect.iscoroutinefunction(fn):

                @functools.wraps(fn)
                async def awrapper(*call_args: Any, **call_kwargs: Any) -> Any:
                    denied = gate(call_args, call_kwargs)
                    return denied if denied is not None else await fn(*call_args, **call_kwargs)

                return awrapper

            @functools.wraps(fn)
            def wrapper(*call_args: Any, **call_kwargs: Any) -> Any:
                denied = gate(call_args, call_kwargs)
                return denied if denied is not None else fn(*call_args, **call_kwargs)

            return wrapper

        return decorate
