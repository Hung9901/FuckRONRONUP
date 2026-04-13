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

        UI_ATTACK ──► PHISHING_INTERACTION  (UI overlay facilitates phishing)
    """

    # Signal names emitted by agents / detectors
    PHISHING_INTERACTION = "PHISHING_INTERACTION"
    PERMISSION_ESCALATION = "PERMISSION_ESCALATION"
    ACCESSIBILITY_RISK = "ACCESSIBILITY_RISK"
    PERSISTENCE_PATTERN = "PERSISTENCE_PATTERN"
    EXFIL_PATTERN = "EXFIL_PATTERN"
    UI_ATTACK = "UI_ATTACK"

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

        Returns a dict with:
          - graph_score:        sum of weights for matched nodes
          - matched_nodes:      list of matched node names
          - full_chain_detected: whether the primary attack chain is complete
          - coverage:           fraction of nodes matched (0.0–1.0)
        """
        score = 0
        matched: list[str] = []

        for name, node in self.nodes.items():
            if name in active_signals:
                score += node.weight
                matched.append(name)

        # Primary chain: all nodes except UI_ATTACK (which is optional entry)
        primary_chain = {
            self.PHISHING_INTERACTION,
            self.PERMISSION_ESCALATION,
            self.ACCESSIBILITY_RISK,
            self.PERSISTENCE_PATTERN,
            self.EXFIL_PATTERN,
        }
        full_chain = primary_chain.issubset(active_signals)
        coverage = len(matched) / len(self.nodes) if self.nodes else 0.0

        return {
            "graph_score": score,
            "matched_nodes": matched,
            "full_chain_detected": full_chain,
            "coverage": round(coverage, 2),
        }

    # ------------------------------------------------------------------
    # Topology
    # ------------------------------------------------------------------

    def _build_default(self) -> None:
        self.add_node(self.UI_ATTACK,             weight=4)
        self.add_node(self.PHISHING_INTERACTION,  weight=3)
        self.add_node(self.PERMISSION_ESCALATION, weight=4)
        self.add_node(self.ACCESSIBILITY_RISK,    weight=4)
        self.add_node(self.PERSISTENCE_PATTERN,   weight=5)
        self.add_node(self.EXFIL_PATTERN,         weight=6)

        self.link(self.UI_ATTACK,             self.PHISHING_INTERACTION)
        self.link(self.PHISHING_INTERACTION,  self.PERMISSION_ESCALATION)
        self.link(self.PERMISSION_ESCALATION, self.ACCESSIBILITY_RISK)
        self.link(self.PERMISSION_ESCALATION, self.PERSISTENCE_PATTERN)
        self.link(self.PERSISTENCE_PATTERN,   self.EXFIL_PATTERN)
