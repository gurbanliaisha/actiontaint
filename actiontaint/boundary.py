from __future__ import annotations

from .models import BoundaryModel, ReachableAction
from .source_classifier import SourceClassifier


class BoundaryModelBuilder:
    """Builds implicit HTTP endpoint models for client-reachable actions."""

    def __init__(self) -> None:
        self.classifier = SourceClassifier()

    def build(self, reachable_actions: list[ReachableAction]) -> list[BoundaryModel]:
        return [self.classifier.build_boundary(reachable) for reachable in reachable_actions]
