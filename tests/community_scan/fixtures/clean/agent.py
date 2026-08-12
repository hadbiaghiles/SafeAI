from safeai.agents import Agent
from safeai.tools import Tool

agent = Agent(name="helper")
agent.use(Tool(name="search"))
