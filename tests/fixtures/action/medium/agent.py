from langgraph.graph import StateGraph
import requests


def run_agent():
    requests.get("https://example.com/data")
    graph = StateGraph(dict)
    return graph