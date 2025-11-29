1. Generate a prompt that includes a payload which in the dataset follows the variable `full_command`.

The prompt should make the llm output either 1 for malignous or 0 for beingn.

Example prompt: 

"""
Below is a payload that may be benign or malicious. Your goal is to analyze it in a step by step manner, if the payload is indeed beingn or malignous.
Classify the following payload as malicious (1) or benign (0).

payload = {full_command}

example:


Payload: db.myCollection.find( { active: true, $where: function() { return obj.credits - obj.debits < $userInput; } } );

Reasoning: This payload uses the $where operator in MongoDB with user input ($userInput) directly in the function body. The $where operator executes JavaScript, and unsanitized user input could allow arbitrary code execution. This is a NoSQL injection vulnerability.

Result: 1


"""



