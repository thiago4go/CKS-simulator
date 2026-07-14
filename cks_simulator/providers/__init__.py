"""Provider-neutral contracts for simulator infrastructure backends."""

from .base import (
    Discovery,
    GuestIdentity,
    KubernetesNode,
    Presence,
    ProcessRequest,
    ProcessResult,
    Provider,
    ProviderHandle,
    ProviderMachine,
    Runner,
    SubprocessRunner,
    bounded_redacted,
    guest_identity_payload,
)

__all__ = [
    "Discovery",
    "GuestIdentity",
    "KubernetesNode",
    "Presence",
    "ProcessRequest",
    "ProcessResult",
    "Provider",
    "ProviderHandle",
    "ProviderMachine",
    "Runner",
    "SubprocessRunner",
    "bounded_redacted",
    "guest_identity_payload",
]
