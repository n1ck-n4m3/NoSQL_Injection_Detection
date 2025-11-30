#!/usr/bin/env python3
"""
Extract classification labels from LLM responses.

This script parses the LLM response field and extracts the label (0 or 1)
into a new field called predicted_llm_response.

Usage:
    python extract_labels.py [model_name]

Examples:
    python extract_labels.py mistral
    python extract_labels.py gemma
    python extract_labels.py llama
    python extract_labels.py qwen
"""

import json
import re
import sys
from typing import Dict, Any, Optional


def extract_label(llm_response: str) -> Optional[str]:
    """
    Extract the label (0 or 1) from LLM response.

    Tries multiple patterns in order of specificity:
    1. JSON format: "label": "0" or "label": "1" (most specific)
    2. Result format: Result: 0 or Result: 1
    3. Check if both 0 and 1 appear - if so, return None (ambiguous)
    4. Single occurrence of 0 or 1

    Args:
        llm_response: The full response from the LLM

    Returns:
        "0" or "1" if found unambiguously, None if ambiguous or not found
    """
    if not llm_response or llm_response.startswith('ERROR:'):
        return None

    # Pattern 1: JSON format "label": "0" or "label": "1" (HIGHEST PRIORITY)
    # This is the most specific and what we asked for in the prompt
    json_pattern = r'"label":\s*"([01])"'
    match = re.search(json_pattern, llm_response)
    if match:
        return match.group(1)

    # Pattern 2: Result: 0 or Result: 1
    result_pattern = r'Result:\s*([01])'
    match = re.search(result_pattern, llm_response, re.IGNORECASE)
    if match:
        return match.group(1)

    # Pattern 3: Find ALL standalone 0 or 1
    simple_pattern = r'\b([01])\b'
    matches = re.findall(simple_pattern, llm_response)

    if not matches:
        return None

    # Check if both 0 and 1 appear - this is ambiguous
    unique_matches = set(matches)
    if len(unique_matches) > 1:
        # Both 0 and 1 found - ambiguous response
        return None

    # Only one unique value (either all 0s or all 1s)
    return matches[0]


def process_dataset(input_path: str, output_path: str, response_field: str = 'mistral_response'):
    """
    Process dataset and extract labels.

    Args:
        input_path: Path to input JSON file
        output_path: Path to output JSON file
        response_field: Name of the response field (e.g., 'mistral_response', 'gemma_response')
    """
    print(f"Loading dataset from {input_path}...")
    with open(input_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    print(f"Processing {len(data)} entries...")

    successful = 0
    failed = 0

    for entry in data:
        llm_response = entry.get(response_field, '')

        # Extract label
        label = extract_label(llm_response)

        if label is not None:
            entry['predicted_llm_response'] = label
            successful += 1
        else:
            entry['predicted_llm_response'] = None
            failed += 1
            # Suppress warnings to reduce output
            # if not llm_response.startswith('ERROR:'):
            #     print(f"Warning: Could not extract label from entry {entry.get('id')}")
            #     print(f"  Response: {llm_response[:100]}...")

    # Save processed dataset
    print(f"\nSaving results to {output_path}...")
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    print(f"\n✓ Processing complete!")
    print(f"  Successfully extracted: {successful}")
    print(f"  Failed to extract: {failed}")
    print(f"  Total: {len(data)}")
    print(f"  Success rate: {successful/len(data)*100:.1f}%")


def main():
    """Main entry point."""
    # Get model name from command line argument
    if len(sys.argv) > 1:
        model_name = sys.argv[1].lower()
    else:
        model_name = 'mistral'
        print("No model specified, defaulting to mistral")
        print("Usage: python extract_labels.py [model_name]")
        print("Available models: mistral, gemma, llama, qwen\n")

    # Define file paths based on model
    model_configs = {
        'mistral': {
            'input': '../data/mistral/nosql_injection_dataset_complete_mistral.json',
            'output': '../data/mistral/nosql_injection_dataset_complete_mistral_labeled.json',
            'response_field': 'mistral_response'
        },
        'gemma': {
            'input': '../data/gemma/gemma.json',
            'output': '../data/gemma/gemma_labeled.json',
            'response_field': 'gemma_response'
        },
        'llama': {
            'input': '../data/llama/llama.json',
            'output': '../data/llama/llama_labeled.json',
            'response_field': 'mistral_response'  # Note: llama.json incorrectly uses mistral_response
        },
        'qwen': {
            'input': '../data/qwen/qwen.json',
            'output': '../data/qwen/qwen_labeled.json',
            'response_field': 'qwen_response'
        }
    }

    if model_name not in model_configs:
        print(f"Error: Unknown model '{model_name}'")
        print(f"Available models: {', '.join(model_configs.keys())}")
        sys.exit(1)

    config = model_configs[model_name]
    print(f"Processing {model_name.upper()} model...")
    print(f"Input:  {config['input']}")
    print(f"Output: {config['output']}")
    print(f"Response field: {config['response_field']}\n")

    try:
        process_dataset(config['input'], config['output'], config['response_field'])
    except FileNotFoundError as e:
        print(f"Error: File not found - {e}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON - {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
