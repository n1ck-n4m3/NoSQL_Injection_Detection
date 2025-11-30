#!/usr/bin/env python3
"""
Gemma 2 9B Evaluator Script

This script reads the nosql_injection_dataset.json file, processes each entry
through the Gemma 2 9B LLM via Ollama, and adds the LLM response to each entry.
"""

import json
import requests
from typing import Dict, List, Any
from pathlib import Path
from tqdm import tqdm


class GemmaEvaluator:
    """Evaluates NoSQL injection payloads using Gemma 2 9B LLM via Ollama."""

    def __init__(
        self,
        model_name: str = "gemma2:9b",
        ollama_url: str = "http://localhost:11434",
        timeout: int = 60
    ):
        """
        Initialize the Gemma evaluator.

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
        template = """You are a NoSQL security expert.
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

    def call_gemma(self, prompt: str) -> str:
        """
        Make API call to Ollama with the prompt.

        Args:
            prompt: The prompt to send to Gemma

        Returns:
            Raw response from Gemma

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
        response = self.call_gemma(prompt)
        return self.parse_response(response)

    def process_dataset(
        self,
        input_path: str,
        output_path: str,
        limit: int = None,
        checkpoint_interval: int = 100,
        checkpoint_dir: str = "results_gemma",
        start_index: int = 0,
        is_resume: bool = False
    ) -> None:
        """
        Process the entire dataset and add Gemma responses.

        Args:
            input_path: Path to input JSON file
            output_path: Path to output JSON file
            limit: Optional limit on number of entries to process
            checkpoint_interval: Save checkpoint every N entries
            checkpoint_dir: Directory to save checkpoints
            start_index: Start processing from this index
            is_resume: Whether this is a resume operation
        """
        print(f"Loading dataset from {input_path}...")
        data = self.load_dataset(input_path)

        # If resuming, load original dataset to get full data
        if is_resume:
            print(f"📂 Resuming from checkpoint with {len(data)} processed entries")
            original_data = self.load_dataset('data/nosql_injection_dataset.json')
            # Merge: keep processed entries, add unprocessed ones
            for i in range(len(data), len(original_data)):
                original_data[i]['gemma_response'] = ''
            if len(data) < len(original_data):
                data = data + original_data[len(data):]
            start_index = len([d for d in data if d.get('gemma_response') and not d['gemma_response'].startswith('ERROR')])
            print(f"🔄 Starting from index {start_index}")

        total_to_process = len(data)
        if limit:
            total_to_process = min(limit, len(data))
            print(f"Processing up to {total_to_process} entries...")
        else:
            print(f"Processing {total_to_process} entries...")

        print(f"Checkpoint interval: every {checkpoint_interval} entries")
        print(f"Checkpoint directory: {checkpoint_dir}/")
        if start_index > 0:
            print(f"Starting from index: {start_index}")

        # Ensure checkpoint directory exists
        Path(checkpoint_dir).mkdir(parents=True, exist_ok=True)

        # Process each entry
        successful = start_index  # Count already processed as successful
        failed = 0
        
        # Only process entries from start_index
        entries_to_process = list(enumerate(data))[start_index:]
        if limit:
            entries_to_process = entries_to_process[:limit - start_index]
        
        print(f"📊 Will process {len(entries_to_process)} entries (index {start_index} to {start_index + len(entries_to_process) - 1})")

        for i, entry in tqdm(entries_to_process, desc="Evaluating with Gemma 2 9B"):
            try:
                full_command = entry.get('full_command', '')
                if not full_command:
                    print(f"Warning: Entry {entry.get('id', 'unknown')} has no full_command")
                    entry['gemma_response'] = 'ERROR: No full_command'
                    failed += 1
                    continue

                # Get Starling's evaluation
                gemma_response = self.evaluate_command(full_command)
                entry['gemma_response'] = gemma_response
                successful += 1

            except Exception as e:
                print(f"\nError processing entry {entry.get('id', 'unknown')}: {e}")
                entry['gemma_response'] = f'ERROR: {str(e)}'
                failed += 1

            # Save checkpoint every N entries
            if (i + 1) % checkpoint_interval == 0:
                checkpoint_path = f"{checkpoint_dir}/checkpoint_{i + 1}.json"
                self.save_dataset(data[:i + 1], checkpoint_path)
                print(f"\n✓ Checkpoint saved: {checkpoint_path} ({successful} successful, {failed} failed)")

        # Save final results
        print(f"\nSaving final results to {output_path}...")
        self.save_dataset(data, output_path)

        # Also save to results folder
        final_checkpoint = f"{checkpoint_dir}/final_results.json"
        self.save_dataset(data, final_checkpoint)

        print(f"\nProcessing complete!")
        print(f"  Successful: {successful}")
        print(f"  Failed: {failed}")
        print(f"  Total: {len(data)}")
        print(f"  Final results: {output_path}")
        print(f"  Also saved to: {final_checkpoint}")

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

    parser = argparse.ArgumentParser(description='Evaluate NoSQL payloads using Gemma 2 9B LLM')
    parser.add_argument(
        '--input',
        default='data/nosql_injection_dataset.json',
        help='Path to input dataset JSON file'
    )
    parser.add_argument(
        '--output',
        default='data/nosql_injection_dataset_with_gemma.json',
        help='Path to output JSON file'
    )
    parser.add_argument(
        '--model',
        default='gemma2:9b',
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
    parser.add_argument(
        '--checkpoint-interval',
        type=int,
        default=100,
        help='Save checkpoint every N entries'
    )
    parser.add_argument(
        '--checkpoint-dir',
        default='results_gemma',
        help='Directory to save checkpoints'
    )
    parser.add_argument(
        '--resume-from',
        type=str,
        default=None,
        help='Resume from a checkpoint file (e.g., results_gemma/checkpoint_4900.json)'
    )
    parser.add_argument(
        '--start-index',
        type=int,
        default=0,
        help='Start processing from this index (0-based)'
    )

    args = parser.parse_args()

    # Initialize evaluator
    evaluator = GemmaEvaluator(
        model_name=args.model,
        ollama_url=args.url,
        timeout=args.timeout
    )

    # Process dataset
    evaluator.process_dataset(
        input_path=args.input if not args.resume_from else args.resume_from,
        output_path=args.output,
        limit=args.limit,
        checkpoint_interval=args.checkpoint_interval,
        checkpoint_dir=args.checkpoint_dir,
        start_index=args.start_index,
        is_resume=args.resume_from is not None
    )


if __name__ == "__main__":
    main()
