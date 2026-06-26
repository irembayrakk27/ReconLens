from groq import Groq
import os
import json

from dotenv import load_dotenv

load_dotenv()

api_key = os.getenv("GROQ_API_KEY")

if not api_key:
    raise ValueError("GROQ_API_KEY bulunamadı!")

client = Groq(api_key=api_key)

def get_ai_analysis(scan_result, rag_context):

    prompt = f"""
    You are a senior SOC analyst specializing in vulnerability assessment, 
    threat intelligence, CVE analysis, and penetration testing.

    Analyze the following reconnaissance results.

    #SCAN RESULTS

    {json.dumps(scan_result, indent=2)}

    #THREAT INTELLIGENCE (RAG)

    {rag_context}


    Generate a professional SOC report using EXACTLY this format.

    Executive Summary

    Affected Service(s)

    Relevant CVEs

    Threat Intelligence

    Risk Analysis

    Mitigation Recommendations

    Priority

    Rules:
    - Be concise and professional.
    - Use only the provided information.
    - Do not invent vulnerabilities.
    - Explain why the risk is important.
    - Mention exploitability when supported by the threat intelligence.
    """

    response = client.chat.completions.create(
        model="llama-3.1-8b-instant",
        messages=[
            {
                "role": "system",
                "content": "You are a senior penetration tester and SOC analyst."
            },
            {
                "role": "user",
                "content": prompt
            }
        ]
    )

    return response.choices[0].message.content

def analyze_report():

    try:

        with open("report.json", "r") as f:
            report_data = json.load(f)

        ai_result = get_ai_analysis(report_data)

        with open("ai_report.txt", "w") as f:
            f.write(ai_result)

        print("[+] AI report saved to ai_report.txt")

    except Exception as e:

        print(f"Analysis Error: {e}")


if __name__ == "__main__":
    analyze_report()