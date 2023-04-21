# eBPF-task
eBPF task for an interview
Task:
Develop a Linux program that detects user actions that involve designated secret values (secrets).
Secrets are strings of the following format: SECRET=<secret_value>\x00 (ASCII encoding).
Secrets may be read from/written to any file.
Every time a secret is read from/written to a file, the program must log such action. 

Requirements:
- The program must use eBPF technology
- The program should be able to filter events by given user id.

Example: 
1. User wants to read file named file_with_secrets.txt that contains ASCII encoded string "SECRET=this is the BIGGEST SECRET in the world!\x00".
2. User executes the following command: "cat file_with_secrets.txt".
3. Developed program should print: Found secret "this is the BIGGEST SECRET in the world!".

Include step-by-step instructions on how to run developed program successfully.
