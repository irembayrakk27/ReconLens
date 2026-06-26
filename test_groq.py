from groq import Groq
import os

client = Groq(api_key=os.environ.get("GROQ_API_KEY"))

response = client.chat.completions.create(
    model="llama3-8b-8192",
    messages=[
        {"role": "user", "content": "ReconLens test çalışıyor mu?"}
    ]
)

print(response.choices[0].message.content)
