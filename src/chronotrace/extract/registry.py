"""Plugin registry discovering and managing artefact extraction plugins."""

from __future__ import annotations
from typing import Dict, List, Type
from chronotrace.extract.base import ArtifactPlugin

_REGISTRY: Dict[str, Type[ArtifactPlugin]] = {}


def register_plugin(plugin_cls: Type[ArtifactPlugin]) -> Type[ArtifactPlugin]:
    """Register an ArtifactPlugin subclass."""
    _REGISTRY[plugin_cls.name] = plugin_cls
    return plugin_cls


def get_plugin(name: str) -> Type[ArtifactPlugin] | None:
    """Retrieve a registered plugin by name."""
    return _REGISTRY.get(name)


def list_plugins() -> List[Type[ArtifactPlugin]]:
    """Return all registered plugins sorted by name."""
    return [cls for _, cls in sorted(_REGISTRY.items())]


def clear_registry() -> None:
    """Clear plugin registry (for testing)."""
    _REGISTRY.clear()
