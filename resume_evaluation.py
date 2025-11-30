#!/usr/bin/env python3
"""
Resume Evaluation Script - Continue from where it stopped
"""

import json
import requests
from tqdm import tqdm
from pathlib import Path

# Configuration
MODEL_NAME = "qwen2.5:7b"
OLLAMA_URL = "http://localhost:11434"
INPUT_FILE = "results/final_results.json"
OUTPUT_FILE = "results/final_results.json"
CHECKPOINT_DIR = "results"
CHECKPOINT_INTERVAL = 100
TIMEOUT = 60

PROMPT_TEMPLATE = """You are a NoSQL security expert.
Here is a command sample and its execution result.
Decide whether it is a MALICIOUS NoSQL injection payload or a BENIGN normal command. Classify the following payload as malicious (1) or benign (0).
If the result is MALICIOUS, the reason must be one of the following
- OPERATOR_INJECTION 
- WHERE_INJECTION 
- REGEX_INJECTION 
- JSON_INJECTION 
- ARRAY_INJECTION 
- OR_INJECTION 
- COMMENT_INJECTION 
- TYPE_CONFUSION 
- AGGREGATION_INJECTION
- MAPREDUCE_INJECTION 
You must consider:
- The query structure and operators
- The description
- Whether execution failed, took too long, affected many docs, etc.
Return a JSON object ONLY in this format:

"label": "1" | "0",
"reason": "short explanation in English"


DO NOT add any extra text.

payload = {full_command}

example:


Payload: db.myCollection.find( {{ active: true, $where: function() {{ return obj.credits - obj.debits < $userInput; }} }} );

Reasoning: This payload uses the $where operator in MongoDB with user input ($userInput) directly in the function body. The $where operator executes JavaScript, and unsanitized user input could allow arbitrary code execution. This is a NoSQL injection vulnerability.

Result: 1

"""


def call_qwen(full_command):
    """Call Qwen via Ollama API"""
    prompt = PROMPT_TEMPLATE.format(full_command=full_command)
    
    try:
        response = requests.post(
            f"{OLLAMA_URL}/api/generate",
            json={
                "model": MODEL_NAME,
                "prompt": prompt,
                "stream": False
            },
            timeout=TIMEOUT
        )
        
        if response.status_code == 200:
            result = response.json()
            return result.get('response', '').strip()
        else:
            raise Exception(f"API returned status {response.status_code}")
            
    except requests.exceptions.Timeout:
        raise Exception(f"Request timed out after {TIMEOUT} seconds")
    except requests.exceptions.ConnectionError:
        raise Exception(f"Cannot connect to Ollama at {OLLAMA_URL}")


def main():
    print(f"📂 Loading data from {INPUT_FILE}...")
    with open(INPUT_FILE, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    # Find entries that need to be re-evaluated (have ERROR responses)
    to_process = []
    for i, entry in enumerate(data):
        resp = entry.get('qwen_response', '')
        if resp.startswith('ERROR') or not resp:
            to_process.append(i)
    
    print(f"📊 Total entries: {len(data)}")
    print(f"🔄 Entries to re-process: {len(to_process)}")
    
    if not to_process:
        print("✅ All entries already processed!")
        return
    
    print(f"\n🚀 Starting from index {to_process[0]} (id={data[to_process[0]].get('id')})")
    print(f"   Checkpoint interval: every {CHECKPOINT_INTERVAL} entries")
    
    # Process entries
    successful = 0
    failed = 0
    
    for count, idx in enumerate(tqdm(to_process, desc="Resuming evaluation")):
        entry = data[idx]
        try:
            full_command = entry.get('full_command', '')
            if not full_command:
                entry['qwen_response'] = 'ERROR: No full_command'
                failed += 1
                continue
            
            response = call_qwen(full_command)
            entry['qwen_response'] = response
            successful += 1
            
        except Exception as e:
            print(f"\n❌ Error at index {idx}: {e}")
            entry['qwen_response'] = f'ERROR: {str(e)}'
            failed += 1
            # If connection error, stop to avoid more errors
            if "Cannot connect" in str(e):
                print("⚠️ Connection lost, saving progress...")
                break
        
        # Save checkpoint
        if (count + 1) % CHECKPOINT_INTERVAL == 0:
            checkpoint_path = f"{CHECKPOINT_DIR}/resume_checkpoint_{count + 1}.json"
            with open(checkpoint_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            print(f"\n✓ Checkpoint saved: {checkpoint_path}")
    
    # Save final results
    print(f"\n💾 Saving results to {OUTPUT_FILE}...")
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    
    print(f"\n✅ Resume complete!")
    print(f"   Successful: {successful}")
    print(f"   Failed: {failed}")
    print(f"   Remaining: {len(to_process) - successful - failed}")


if __name__ == "__main__":
    main()

