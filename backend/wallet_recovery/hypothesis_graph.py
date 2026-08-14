"""Non-secret recovery hypothesis graph with cost-aware pruning."""

from dataclasses import dataclass, field


@dataclass
class HypothesisNode:
    node_id: str
    kind: str
    value: str
    confidence: float
    estimated_cost: int = 0
    eliminated: bool = False
    children: list[str] = field(default_factory=list)


class RecoveryHypothesisGraph:
    def __init__(self): self.nodes = {}
    def add(self, node: HypothesisNode): self.nodes[node.node_id] = node; return node
    def link(self, parent: str, child: str):
        if parent in self.nodes and child in self.nodes: self.nodes[parent].children.append(child)
    def eliminate_subtree(self, node_id: str):
        node = self.nodes.get(node_id)
        if not node: return
        node.eliminated = True
        for child in node.children: self.eliminate_subtree(child)
    def ranked(self): return sorted((node for node in self.nodes.values() if not node.eliminated), key=lambda n: (-n.confidence, n.estimated_cost))
    def sanitized(self): return [{"node_id": n.node_id, "kind": n.kind, "value": n.value, "confidence": n.confidence, "estimated_cost": n.estimated_cost, "eliminated": n.eliminated, "children": list(n.children)} for n in self.nodes.values()]
