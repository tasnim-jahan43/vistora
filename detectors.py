import re

# Detect instruction bypass
RE_IGNORE = re.compile(r"(?i)\b(ignore|disregard|forget|override|do not follow)\b")

# Detect long suspicious Base64-like text
RE_BASE64 = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")

def detect_prompt(prompt: str):
    reasons = []

    if RE_IGNORE.search(prompt):
        reasons.append("ignore_instruction")

    if RE_BASE64.search(prompt):
        reasons.append("suspicious_base64")

    return reasons
