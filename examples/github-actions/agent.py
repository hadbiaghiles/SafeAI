"""Small synthetic agent used by the SafeAI GitHub Actions example."""

from typing import TypedDict

from langgraph.graph import END, START, StateGraph


class AgentState(TypedDict):
    message: str
    response: str


def respond(state: AgentState) -> AgentState:
    """Return a deterministic response without external side effects."""
    return {**state, "response": "The synthetic agent completed successfully."}


def build_agent():
    graph = StateGraph(AgentState)
    graph.add_node("respond", respond)
    graph.add_edge(START, "respond")
    graph.add_edge("respond", END)
    return graph.compile()
