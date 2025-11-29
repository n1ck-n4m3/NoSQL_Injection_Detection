#!/usr/bin/env python3
"""
Mistral Evaluator Script

This script reads the nosql_injection_dataset.json file, processes each entry
through the Mistral LLM via Ollama, and adds the LLM response to each entry.
"""

import json
import requests
from typing import Dict, List, Any
from pathlib import Path
from tqdm import tqdm


class MistralEvaluator:
    """Evaluates NoSQL injection payloads using Mistral LLM via Ollama."""

    def __init__(
        self,
        model_name: str = "mistral:7b",
        ollama_url: str = "http://localhost:11434",
        timeout: int = 60
    ):
        """
        Initialize the Mistral evaluator.

        Args:
            model_name: Name of the Ollama model to use
            ollama_url: URL of the Ollama API
            timeout: Request timeout in seconds
        """
        self.model_name = model_name
        self.ollama_url = ollama_url
        self.timeout = timeout
        self.prompt_template = self._get_prompt_template()

    def _get_prompt_template(self) -> str:
        """
        Get the prompt template for classification.

        Returns:
            The prompt template string
        """
        template = """Below is a payload that may be benign or malicious. Your goal is to analyze it in a step by step manner, if the payload is indeed beingn or malignous.
Classify the following payload as malicious (1) or benign (0).

payload = {full_command}

example:


Payload: db.myCollection.find( {{ active: true, $where: function() {{ return obj.credits - obj.debits < $userInput; }} }} );

Reasoning: This payload uses the $where operator in MongoDB with user input ($userInput) directly in the function body. The $where operator executes JavaScript, and unsanitized user input could allow arbitrary code execution. This is a NoSQL injection vulnerability.

Result: 1

"""
        return template

    def create_prompt(self, full_command: str) -> str:
        """
        Create the full prompt by inserting the command.

        Args:
            full_command: The MongoDB command to analyze

        Returns:
            The complete prompt string
        """
        return self.prompt_template.format(full_command=full_command)

    def call_mistral(self, prompt: str) -> str:
        """
        Make API call to Ollama with the prompt.

        Args:
            prompt: The prompt to send to Mistral

        Returns:
            Raw response from Mistral

        Raises:
            Exception: If API call fails
        """
        try:
            response = requests.post(
                f"{self.ollama_url}/api/generate",
                json={
                    "model": self.model_name,
                    "prompt": prompt,
                    "stream": False
                },
                timeout=self.timeout
            )

            if response.status_code == 200:
                result = response.json()
                return result.get('response', '')
            else:
                raise Exception(f"API returned status {response.status_code}: {response.text}")

        except requests.exceptions.Timeout:
            raise Exception(f"Request timed out after {self.timeout} seconds")
        except requests.exceptions.ConnectionError:
            raise Exception(f"Cannot connect to Ollama at {self.ollama_url}")
        except Exception as e:
            raise Exception(f"API call failed: {str(e)}")

    def parse_response(self, response: str) -> str:
        """
        Parse the LLM response to extract classification.

        Args:
            response: Raw LLM response

        Returns:
            The full LLM response as string
        """
        # Return the full response for now
        # We can add parsing logic later if needed
        return response.strip()

    def evaluate_command(self, full_command: str) -> str:
        """
        Evaluate a single MongoDB command.

        Args:
            full_command: The MongoDB command to evaluate

        Returns:
            LLM response/classification
        """
        prompt = self.create_prompt(full_command)
        response = self.call_mistral(prompt)
        return self.parse_response(response)

    def process_dataset(
        self,
        input_path: str,
        output_path: str,
        limit: int = None
    ) -> None:
        """
        Process the entire dataset and add Mistral responses.

        Args:
            input_path: Path to input JSON file
            output_path: Path to output JSON file
            limit: Optional limit on number of entries to process
        """
        print(f"Loading dataset from {input_path}...")
        data = self.load_dataset(input_path)

        if limit:
            data = data[:limit]
            print(f"Processing first {limit} entries...")
        else:
            print(f"Processing {len(data)} entries...")

        # Process each entry
        successful = 0
        failed = 0

        for entry in tqdm(data, desc="Evaluating payloads"):
            try:
                full_command = entry.get('full_command', '')
                if not full_command:
                    print(f"Warning: Entry {entry.get('id', 'unknown')} has no full_command")
                    entry['mistral_response'] = 'ERROR: No full_command'
                    failed += 1
                    continue

                # Get Mistral's evaluation
                mistral_response = self.evaluate_command(full_command)
                entry['mistral_response'] = mistral_response
                successful += 1

            except Exception as e:
                print(f"\nError processing entry {entry.get('id', 'unknown')}: {e}")
                entry['mistral_response'] = f'ERROR: {str(e)}'
                failed += 1

        # Save results
        print(f"\nSaving results to {output_path}...")
        self.save_dataset(data, output_path)

        print(f"\nProcessing complete!")
        print(f"  Successful: {successful}")
        print(f"  Failed: {failed}")
        print(f"  Total: {len(data)}")

    def load_dataset(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Load dataset from JSON file.

        Args:
            file_path: Path to the JSON file

        Returns:
            List of dataset entries
        """
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return data

    def save_dataset(self, data: List[Dict[str, Any]], file_path: str) -> None:
        """
        Save dataset to JSON file.

        Args:
            data: List of dataset entries
            file_path: Path to save the JSON file
        """
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)


def main():
    """Main entry point for the script."""
    import argparse

    parser = argparse.ArgumentParser(description='Evaluate NoSQL payloads using Mistral LLM')
    parser.add_argument(
        '--input',
        default='../data/nosql_injection_dataset.json',
        help='Path to input dataset JSON file'
    )
    parser.add_argument(
        '--output',
        default='../data/nosql_injection_dataset_with_mistral.json',
        help='Path to output JSON file'
    )
    parser.add_argument(
        '--model',
        default='mistral:7b',
        help='Ollama model name'
    )
    parser.add_argument(
        '--url',
        default='http://localhost:11434',
        help='Ollama API URL'
    )
    parser.add_argument(
        '--limit',
        type=int,
        default=None,
        help='Limit number of entries to process (for testing)'
    )
    parser.add_argument(
        '--timeout',
        type=int,
        default=60,
        help='Request timeout in seconds'
    )

    args = parser.parse_args()

    # Initialize evaluator
    evaluator = MistralEvaluator(
        model_name=args.model,
        ollama_url=args.url,
        timeout=args.timeout
    )

    # Process dataset
    evaluator.process_dataset(
        input_path=args.input,
        output_path=args.output,
        limit=args.limit
    )


if __name__ == "__main__":
    main()
