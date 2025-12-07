from detectors import detect_prompt

def policy_engine(prompt: str):
    issues = detect_prompt(prompt)

    # If problematic parts found → sanitize
    safe_prompt = prompt
    action = "allow"

    if "ignore_instruction" in issues:
        safe_prompt = safe_prompt.replace("ignore", "[blocked_word]")
        action = "sanitize"

    if "suspicious_base64" in issues:
        safe_prompt = "[Base64 Removed for Safety]"
        action = "sanitize"

    # If no issues → allow normally
    return safe_prompt, action
