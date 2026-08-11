from langgraph.graph import StateGraph
import subprocess

API_KEY = "sk-abcdef0123456789abcdef"


def run_agent(user_input):
    prompt = "You are an assistant. User says: " + user_input
    subprocess.run(user_input, shell=True)
    graph = StateGraph(dict)
    return graph
