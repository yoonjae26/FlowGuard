"""Toolbox: a guarded tool registry with a ready-made dispatcher for LLM tool-calling loops.

Works with any provider whose tool calls arrive as ``(name, arguments)``:
OpenAI ``tool_calls``, Anthropic ``tool_use`` blocks, and so on.
"""

from __future__ import annotations

import inspect
import json
from collections.abc import Callable, Iterable
from typing import Any

from .decision import FlowBlocked
from .guard import Guard


class Toolbox:
    """Register tools as sources, sinks or neutral tools, then call :meth:`dispatch`.

    Denials are returned to the model as a short, generic string
    (:attr:`Decision.public_reason`) unless ``verbose_denials=True``; the
    detailed reason always goes to the audit log.
    """

    def __init__(self, guard: Guard, *, verbose_denials: bool = False):
        self.guard = guard
        self.verbose_denials = verbose_denials
        self._tools: dict[str, Callable[..., Any]] = {}

    def _add(self, name: str | None, fn: Callable[..., Any], wrapped: Callable[..., Any]) -> Callable[..., Any]:
        self._tools[name or fn.__name__] = wrapped
        return wrapped

    def tool(self, fn: Callable[..., Any] | None = None, *, name: str | None = None):
        """Register a neutral tool (neither reads nor sends sensitive data)."""

        def decorate(f: Callable[..., Any]) -> Callable[..., Any]:
            return self._add(name, f, f)

        return decorate(fn) if fn is not None else decorate

    def source(self, fn: Callable[..., Any] | None = None, *, name: str | None = None):
        """Register a tool whose results may contain sensitive data."""

        def decorate(f: Callable[..., Any]) -> Callable[..., Any]:
            return self._add(name, f, self.guard.source(name or f.__name__)(f))

        return decorate(fn) if fn is not None else decorate

    def sink(
        self,
        fn: Callable[..., Any] | None = None,
        *,
        destination: str | Callable[..., Any],
        name: str | None = None,
        args: Iterable[str] | None = None,
    ):
        """Register a tool that sends data somewhere. See :meth:`Guard.sink`."""

        def decorate(f: Callable[..., Any]) -> Callable[..., Any]:
            guarded = self.guard.sink(destination, args=args, tool=name or f.__name__, on_block="raise")(f)
            return self._add(name, f, guarded)

        return decorate(fn) if fn is not None else decorate

    # -- dispatch ------------------------------------------------------

    def _prepare(self, name: str, arguments: str | dict | None) -> tuple[Callable[..., Any] | None, dict, str | None]:
        fn = self._tools.get(name)
        if fn is None:
            return None, {}, f"error: unknown tool {name!r}"
        if arguments is None:
            arguments = {}
        if isinstance(arguments, str):
            try:
                arguments = json.loads(arguments) if arguments.strip() else {}
            except ValueError:
                return None, {}, "error: tool arguments are not valid JSON"
        if not isinstance(arguments, dict):
            return None, {}, "error: tool arguments must be a JSON object"
        return fn, arguments, None

    def _denied(self, exc: FlowBlocked) -> str:
        return exc.decision.reason if self.verbose_denials else exc.decision.public_reason

    @staticmethod
    def _render(result: Any) -> str:
        return result if isinstance(result, str) else json.dumps(result, default=str)

    def dispatch(self, name: str, arguments: str | dict | None = None) -> str:
        """Run a tool call and return the string to hand back to the model."""
        fn, kwargs, error = self._prepare(name, arguments)
        if fn is None:
            return error or ""
        try:
            result = fn(**kwargs)
            if inspect.isawaitable(result):
                if inspect.iscoroutine(result):
                    result.close()  # never awaited: avoid a "coroutine was never awaited" warning
                raise TypeError(f"tool {name!r} is async; use adispatch()")
        except FlowBlocked as exc:
            return self._denied(exc)
        except Exception as exc:  # tool bugs must not crash the agent loop
            return f"error: {type(exc).__name__}: {exc}"
        return self._render(result)

    async def adispatch(self, name: str, arguments: str | dict | None = None) -> str:
        fn, kwargs, error = self._prepare(name, arguments)
        if fn is None:
            return error or ""
        try:
            result = fn(**kwargs)
            if inspect.isawaitable(result):
                result = await result
        except FlowBlocked as exc:
            return self._denied(exc)
        except Exception as exc:
            return f"error: {type(exc).__name__}: {exc}"
        return self._render(result)
