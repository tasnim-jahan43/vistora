from transformers import pipeline
from policy_engine import policy_engine

# Load GPT2 model
model = pipeline("text-generation", model="sshleifer/tiny-gpt2")

def call_ai_model(prompt):
    safe_prompt, action = policy_engine(prompt)
    response = model(safe_prompt, max_length=100, num_return_sequences=1)
    return response[0]['generated_text'], action


# ---- Test Run ----
if __name__ == "__main__":
    print("Enter prompt:")
    user_input = input("> ")

    output, action = call_ai_model(user_input)

    print("\n=== POLICY ENGINE ACTION ===")
    print(action)

    print("\n=== MODEL OUTPUT ===")
    print(output)
