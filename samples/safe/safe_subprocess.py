import json
import subprocess

name = input("Enter your name: ")

message = "Hello, " + name
print(message)

# Safe: JSON handles untrusted serialization needs.
data = json.loads('{"greeting": "hello"}')

# Safe: argument list without shell=True avoids shell injection.
subprocess.run(["ping", "-c", "1", "localhost"], shell=False)
