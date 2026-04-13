class AttackNode:
    def __init__(self, name: str, weight: int):
        self.name = name
        self.weight = weight
        self.children: list["AttackNode"] = []


class AttackGraph:
    """
    Weighted directed graph of behavioral attack signals.

    Nodes represent observable threat indicators; edges model the causal
    chain (e.g. PHISHING_INTERACTION triggers PERMISSION_ESCALATION).
    evaluate() sums weights for every node whose signal is currently active.

    Default graph topology:

        PHISHING_INTERACTION ──► PERMISSION_ESCALATION ──► ACCESSIBILITY_RISK
                                          │
                                          ▼
                                 PERSISTENCE_PATTERN
                                          │
                                          ▼
                                   EXFIL_PATTERN
    """

    # Signal names emitted by agents / detectors
    PHISHING_INTERACTION = "PHISHING_INTERACTION"
    PERMISSION_ESCALATION = "PERMISSION_ESCALATION"
    ACCESSIBILITY_RISK = "ACCESSIBILITY_RISK"
    PERSISTENCE_PATTERN = "PERSISTENCE_PATTERN"
    EXFIL_PATTERN = "EXFIL_PATTERN"

    def __init__(self):
        self.nodes: dict[str, AttackNode] = {}
        self._build_default()

    # ------------------------------------------------------------------
    # Graph construction helpers
    # ------------------------------------------------------------------

    def add_node(self, name: str, weight: int) -> None:
        self.nodes[name] = AttackNode(name, weight)

    def link(self, parent: str, child: str) -> None:
        self.nodes[parent].children.append(self.nodes[child])

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------

    def evaluate(self, active_signals: set[str]) -> dict:
        """
        Score the graph against a set of active signal names.

        Returns a dict with total score, matched nodes, and
        whether the full attack chain is present.
        """
        score = 0
        matched: list[str] = []

        for name, node in self.nodes.items():
            if name in active_signals:
                score += node.weight
                matched.append(name)

        full_chain = set(self.nodes.keys()).issubset(active_signals)

        return {
            "graph_score": score,
            "matched_nodes": matched,
            "full_chain_detected": full_chain,
        }

    # ------------------------------------------------------------------
    # Topology
    # ------------------------------------------------------------------

    def _build_default(self) -> None:
        self.add_node(self.PHISHING_INTERACTION,  weight=3)
        self.add_node(self.PERMISSION_ESCALATION, weight=4)
        self.add_node(self.ACCESSIBILITY_RISK,    weight=4)
        self.add_node(self.PERSISTENCE_PATTERN,   weight=5)
        self.add_node(self.EXFIL_PATTERN,         weight=6)

        self.link(self.PHISHING_INTERACTION,  self.PERMISSION_ESCALATION)
        self.link(self.PERMISSION_ESCALATION, self.ACCESSIBILITY_RISK)
        self.link(self.PERMISSION_ESCALATION, self.PERSISTENCE_PATTERN)
        self.link(self.PERSISTENCE_PATTERN,   self.EXFIL_PATTERN)
