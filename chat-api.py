import requests
import os

# Load Copilot token from environment variable (set GITHUB_TOKEN or COPILOT_TOKEN)
COPILOT_TOKEN = os.environ.get("GITHUB_TOKEN") or os.environ.get("COPILOT_TOKEN", "")
if not COPILOT_TOKEN:
    raise ValueError("No token found. Set GITHUB_TOKEN or COPILOT_TOKEN environment variable.")

# GitHub Copilot chat completions endpoint (no /v1/)
url = "https://api.githubcopilot.com/chat/completions"
headers = {
    "Authorization": f"Bearer {COPILOT_TOKEN}",
    "Content-Type": "application/json",
    "Editor-Version": "vscode/1.85.0",
    "Editor-Plugin-Version": "copilot/1.138.0",
    "User-Agent": "GithubCopilot/1.138.0"
}
data = {
    "messages": [
        {"role": "user", "content": "What are the SQL tables by checking the MCP connection"}
    ],
    "model": "gpt-4",  # or "gpt-3.5-turbo"
    "stream": False
}


response = requests.post(url, headers=headers, json=data, verify=False)
# Print the raw response for debugging
print("Raw response:\n", response.text)
try:
    result = response.json()
    print("\nParsed JSON response:\n", result)
except Exception as e:
    print("\nError parsing JSON response:", e)
