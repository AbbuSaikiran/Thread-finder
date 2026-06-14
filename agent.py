import os
import sys
from dotenv import load_dotenv
from langchain_core.tools import tool
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.messages import AIMessage, HumanMessage
from langchain.agents import AgentExecutor, create_tool_calling_agent

# Load environment variables from .env file
load_dotenv()

# Verify API keys
has_openai = bool(os.getenv("OPENAI_API_KEY"))
has_google = bool(os.getenv("GOOGLE_API_KEY") and not os.getenv("GOOGLE_API_KEY").startswith("<"))

if not has_openai and not has_google:
    print("Error: Neither OPENAI_API_KEY nor GOOGLE_API_KEY is configured in your .env file.")
    print("Please add an active API key to your .env file to run the agent.")
    sys.exit(1)

# Initialize the Chat Model
if has_openai:
    from langchain_openai import ChatOpenAI
    print("Initializing Agent with OpenAI (gpt-4o-mini)...")
    llm = ChatOpenAI(model="gpt-4o-mini", temperature=0.7)
else:
    from langchain_google_genai import ChatGoogleGenerativeAI
    print("Initializing Agent with Google Gemini (gemini-2.0-flash)...")
    llm = ChatGoogleGenerativeAI(model="gemini-2.0-flash", temperature=0.7)

# Define Tools
@tool
def get_weather(city: str) -> str:
    """Get the current weather forecast for a city."""
    return f"The weather in {city} is sunny, 72°F, with a light breeze of 5 mph."

@tool
def calculate_expression(expression: str) -> str:
    """Evaluate a mathematical expression. Input should be a mathematical string like '2 + 2 * 3'."""
    try:
        # Safe character evaluation
        allowed_chars = set("0123456789+-*/(). ")
        if not all(char in allowed_chars for char in expression):
            return "Error: Invalid characters in expression."
        result = eval(expression, {"__builtins__": None}, {})
        return f"Result: {result}"
    except Exception as e:
        return f"Error evaluating expression: {e}"

tools = [get_weather, calculate_expression]

# Define Chat Prompt Template
prompt = ChatPromptTemplate.from_messages([
    ("system", "You are a helpful and intelligent AI assistant. Use your tools when necessary to answer the user's questions."),
    MessagesPlaceholder(variable_name="chat_history"),
    ("human", "{input}"),
    MessagesPlaceholder(variable_name="agent_scratchpad"),
])

# Create the Agent and Agent Executor
agent = create_tool_calling_agent(llm, tools, prompt)
agent_executor = AgentExecutor(agent=agent, tools=tools, verbose=True)

def main():
    chat_history = []
    print("\n=== LLM Agent CLI Chat Initialized ===")
    print("Ask any question (e.g. 'What is 45 * 12 + 10?' or 'What is the weather in New York?')")
    print("Type 'exit' or 'quit' to stop.\n")
    
    while True:
        try:
            user_input = input("You: ").strip()
            if not user_input:
                continue
            if user_input.lower() in ["exit", "quit"]:
                print("Exiting chat. Goodbye!")
                break
                
            response = agent_executor.invoke({
                "input": user_input,
                "chat_history": chat_history
            })
            
            # Save message history
            chat_history.append(HumanMessage(content=user_input))
            chat_history.append(AIMessage(content=response["output"]))
            
            print(f"\nAgent: {response['output']}\n")
            
        except KeyboardInterrupt:
            print("\nExiting chat. Goodbye!")
            break
        except Exception as e:
            print(f"\nError: {e}\n")

if __name__ == "__main__":
    main()
