# SCRIBE

SCRIBE is a lightweight, high-performance file analysis tool designed for static string extraction. It allows researchers to pull human-readable data, logic, and network artifacts out of binary files (like `.exe`, `.dll`, or `.sys`) without executing them.

By treating files as raw data, SCRIBE bypasses common malware defenses such as Anti-VM, Anti-Debugging, and Anti-Cheat triggers.

## Key Features

- **Multi-Mode Analysis**:
  - **Normal**: View the raw "DNA" of the file, including system APIs and assembly debris.
  - **Strict**: Filters out noise/symbols and automatically repairs "spaced-out" UTF-16 strings (e.g., `R o b l o x` -> `Roblox`).
  - **ASM (Aggressive Strict Mode)**: Strips everything except pure human-readable sentences and words.
  - **URLs**: Specifically hunts for web endpoints, IP addresses, and communication hooks.


## How to Use

## Direct Analysis
1. Click **Open File**.
2. Select any binary file (even those that refuse to open in standard editors).
3. Switch between modes to instantly re-analyze the data.

### Method 2: The Notepad Dump
1. Drag a file into notepad perferably windows 10 notepad since its way more lightweight and can handle big files without lag you can find it in "C:\Windows\notepad.exe"
2. Copy all of that what seems like useless code
3. Paste it all into the input box
4. The extraction will happen automatically.

## Use Cases
- **Malware Research**: Quickly identify C2 (Command & Control) servers and hidden file paths.
- **Game Analysis**: Extract offsets, version numbers, and engine configurations.
- **Forensics**: Find hidden messages or developer comments within compiled code.

## Requirements
- Python 3.x
- No external libraries required (uses standard `tkinter` and `re`).
