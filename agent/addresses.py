"""Email address parsing and the rules for who may invoke the agent.

The previous implementation tested `owner_email not in (to + cc + from)`, a raw
substring check against three concatenated headers. That accepted any address
ending in the owner's address, so "xanntaod@gmail.com" passed as
"anntaod@gmail.com". Everything here parses addresses properly instead.
"""

from dataclasses import dataclass
from email.utils import getaddresses, parseaddr
from typing import Iterable, Optional


def parse_addresses(*header_values: Optional[str]) -> list[str]:
    """Extract normalised addresses from any number of address headers."""
    pairs = getaddresses([v for v in header_values if v])
    seen: list[str] = []
    for _, addr in pairs:
        addr = addr.strip().lower()
        if addr and "@" in addr and addr not in seen:
            seen.append(addr)
    return seen


def sender_address(from_header: Optional[str]) -> str:
    """Return the bare address from a From header, lowercased."""
    return parseaddr(from_header or "")[1].strip().lower()


def display_name(from_header: Optional[str]) -> str:
    """Return the display name from a From header, or the local part as a fallback."""
    name, addr = parseaddr(from_header or "")
    name = name.strip().strip('"').strip()
    if name:
        return name
    return addr.split("@", 1)[0] if addr else ""


def matches_allowlist(address: str, allowlist: Iterable[str]) -> bool:
    """True if the address is listed directly or its domain is listed as @domain."""
    entries = set(allowlist)
    if not entries:
        return True
    address = address.lower()
    if address in entries:
        return True
    domain = address.rpartition("@")[2]
    return bool(domain) and (f"@{domain}" in entries or domain in entries)


@dataclass(frozen=True)
class Authorization:
    allowed: bool
    reason: str
    sender: str
    participants: tuple[str, ...]


def authorize(
    *,
    from_header: Optional[str],
    to_header: Optional[str],
    cc_header: Optional[str],
    agent_email: str,
    owner_email: str,
    allowlist: Iterable[str] = (),
) -> Authorization:
    """Decide whether this thread may be acted on, and by whom.

    Three conditions must hold:

    1. The agent is explicitly addressed in To or Cc. Being merely mentioned in a
       forwarded body is not an invitation.
    2. The owner is a genuine parsed participant of the thread.
    3. The sender passes the allowlist, when one is configured.
    """
    agent_email = agent_email.lower()
    owner_email = owner_email.lower()

    sender = sender_address(from_header)
    addressed = set(parse_addresses(to_header, cc_header))
    everyone = parse_addresses(from_header, to_header, cc_header)
    others = tuple(a for a in everyone if a not in {agent_email, owner_email})

    if not sender:
        return Authorization(False, "no parsable sender address", sender, others)

    if sender == agent_email:
        return Authorization(False, "message was sent by the agent itself", sender, others)

    if agent_email not in addressed:
        return Authorization(False, "agent is not in To or Cc", sender, others)

    if owner_email not in set(everyone):
        return Authorization(False, f"owner {owner_email} is not a participant", sender, others)

    if not matches_allowlist(sender, allowlist):
        return Authorization(False, f"sender {sender} is not on the allowlist", sender, others)

    return Authorization(True, "ok", sender, others)


def reply_recipients(
    *,
    from_header: Optional[str],
    to_header: Optional[str],
    cc_header: Optional[str],
    agent_email: str,
    owner_email: str,
) -> tuple[str, str]:
    """Return (to_field, cc_field) for the agent's reply.

    Everyone except the agent goes in To; the owner is always Cc'd unless they
    are already in To. Falls back to the original sender when nothing else parses.
    """
    everyone = parse_addresses(from_header, to_header, cc_header)
    to_list = [a for a in everyone if a not in {agent_email.lower(), owner_email.lower()}]

    if not to_list:
        sender = sender_address(from_header)
        if sender and sender != agent_email.lower():
            to_list = [sender]

    cc = owner_email if owner_email.lower() not in to_list else ""
    return ", ".join(to_list), cc
