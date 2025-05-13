from google import genai
from google.genai import types
from google.genai.types import Tool, GoogleSearch, GenerateContentConfig

class PortVulnerabilities:
    def GemResponses(ports):
        client = genai.Client(
            api_key = "API_KEY"
        )
        response = client.models.generate_content_stream(
            model= "gemini-2.5-flash-preview-04-17",
            contents = [f"You are a redHat cyberSec engineer with descriptive answers. list 3 Vulnerabilities for each port:", ports, "; make each index no more than 50 words, take away all warnings. You Will not introduce yourself in this prompt"],
            config = types.GenerateContentConfig(
                thinking_config=types.ThinkingConfig(thinking_budget=4096),
                temperature = .2
                )
        )
        for x in response:
            print(x.text,end="")
        print("")
