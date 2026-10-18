"""Scope guard — ensures the agent only touches authorised hosts."""
from urllib.parse import urlparse


def _host_of(target: str) -> str:
    t = target if "://" in target else f"http://{target}"
    return (urlparse(t).hostname or "").lower()


def allowed_hosts(scope: list[str]) -> set[str]:
    return {_host_of(s) for s in (scope or []) if _host_of(s)}


def is_in_scope(target: str, scope: list[str]) -> bool:
    """True if target's host is in scope. Empty scope = deny-all (fail closed)."""
    allowed = allowed_hosts(scope)
    if not allowed:
        return False
    return _host_of(target) in allowed


class ScopeError(Exception):
    pass


def assert_in_scope(target: str, scope: list[str]) -> None:
    if not is_in_scope(target, scope):
        raise ScopeError(
            f"Target host '{_host_of(target)}' is not in authorised scope {sorted(allowed_hosts(scope))}. "
            f"Refusing to send requests (fail-closed)."
        )
