from chromadb import Collection, PersistentClient
from requests import Response, post
import uuid
import json
import sys
import re
import os

os.chdir("./tools")

api_url="http://192.168.1.252:11434"
model = sys.argv[1]
username = sys.argv[2]


def determine_memory_mode(user_message: str) -> bool:
    if user_message.startswith("/save"):
        user_message = user_message.replace("/save", "")
        return "save"
    if user_message.startswith("/recall"):
        user_message = user_message.replace("/recall", "")
        return "recall"
    if user_message.startswith("/reset"):
        user_message = user_message.replace("/reset", "")
        return "reset"

    raise Exception("Cannot determine memory working mode, failover")

def embed(model: str, inputd: str) -> Response:
  response = post(f"{api_url}/api/embed", 
    data=json.dumps({
        'model': model,
        'input': inputd,
    }),
    headers={
      "Content-Type": "application/json"
    }
  )
  if not response.ok:
    raise Exception(f"Server couldnt create an embed: {response.status_code}")
  return response

def reset():
    client = PersistentClient(path="./memstore/")
    collection = client.get_or_create_collection(name=f"{username}_data")
    client.reset()
    print("CONTEXT: Your memory has been reset, forget everything")

def writedown(documents: list):
    client = PersistentClient(path="./memstore/")
    collection = client.get_or_create_collection(name=f"{username}_data")
    for i, d in enumerate(documents):
        response = json.loads(embed(model, d).content)
        embeddings = response["embeddings"]
        id = str(uuid.uuid4())
        collection.upsert(
           ids=[id],
           embeddings=embeddings,
           documents=d
        )
        
    print("CONTEXT: Your memory has been saved successfully, forget everything till this point, inform the user about success")

def remember():
    client = PersistentClient(path="./memstore/")
    collection = client.get_or_create_collection(name=f"{username}_data")
    response = json.loads(embed(
        model,
        user_message
        ).content
    )
    results = collection.query(
        query_embeddings=response["embeddings"],
        n_results=5
    )
    data = results['documents'][0]
    if data:
        datastr = ""
        for ds in data:
            if ds:
                datastr += ds + ";"
        memory = datastr.strip()
        if memory.startswith("/save"):
            memory = memory.replace("/save", "")
        user_context = f"MEMORY: \"{memory.strip()} Ignore earlier messages, use this memory to answer the user.\""
        print(user_context.strip())

with open(f"{username}_message", mode="r") as f:
   user_message = f.read()
   mode = None
   try:
        mode = determine_memory_mode(user_message=user_message)
   except Exception as e:
        print("CONTEXT: No memories found nor requested")
        exit(0)
   match mode:
        case "save":
            d = re.split(r'(?<!\w\.\w.)(?<![A-Z][a-z]\.)(?<=\.|\?|\!)\s+', user_message)
            writedown(d)
        case "recall":
            remember()
        case "reset":
            reset()
