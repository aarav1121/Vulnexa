import os
import pickle
import subprocess

user_input = input("Enter command: ")

# VULN-002: dynamic statement execution
exec(user_input)

# VULN-003: unsafe deserialization of untrusted data
data = pickle.loads(user_input.encode())

# VULN-004: shell command execution with untrusted input
os.system("echo " + user_input)

# VULN-005: subprocess through the system shell
subprocess.run("ping " + user_input, shell=True)
