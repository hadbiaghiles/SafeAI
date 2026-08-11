from langgraph.graph import StateGraph

STATE = {"messages": []}


def build_agent():
    graph = StateGraph(dict)
    graph.set_entry_point("echo")

    def echo(state):
        return {"messages": state.get("messages", []) + ["ok"]}

    graph.add_node("echo", echo)
    return graph.compile()
