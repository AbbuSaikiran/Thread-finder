import openai
from dotenv import load_dotenv
from langsmith import traceable
from langsmith.wrappers import wrap_openai

# Load environment variables from .env file
load_dotenv()

client = wrap_openai(openai.Client())


@traceable(run_type="tool", name="Retrieve Context")
def my_tool(question: str) -> str:
    return "During this morning's meeting, we solved all world conflict."


@traceable(name="Chat Pipeline")
def chat_pipeline(question: str):
    context = my_tool(question)
    messages = [
        {
            "role": "system",
            "content": "You are a helpful assistant. Please respond to the user's request only based on the given context.",
        },
        {
            "role": "user",
            "content": f"Question: {question}\nContext: {context}",
        },
    ]
    chat_completion = client.chat.completions.create(
        model="gpt-4o-mini", messages=messages
    )
    return chat_completion.choices[0].message.content


if __name__ == "__main__":
    try:
        result = chat_pipeline("Can you summarize this morning's meetings?")
        print(result)
    except openai.RateLimitError as e:
        print(f"\nOpenAI Quota Limit Exceeded: {e}")
        print("Your OpenAI API Key is valid, but the account has insufficient billing quota. Please check your OpenAI plan.")
    except Exception as e:
        print(f"\nAn error occurred: {e}")

