# SCRIBE

SCRIBE is a lightweight, high-performance file analysis tool designed for static string extraction. It allows researchers to pull human-readable data, logic, and network artifacts out of binary files (like `.exe`, `.dll`, or `.sys`) without executing them.

By treating files as raw data, SCRIBE bypasses common malware defenses such as Anti-VM, Anti-Debugging, and Anti-Cheat triggers.

## Key Features

- **Multi-Mode Analysis**:
  - **Normal**: View the binary file in minimal filtering might be better for more data incase others filter out important data
  - **Strict**: Filters out noise/symbols and automatically repairs "spaced-out" UTF-16
  - **ASM (Aggressive Strict Mode)**: Strips everything except pure human-readable sentences and words.(needs improvements)
  - **URLs**: Specifically looks for urls doesnt work well
  - **Paths**: Specifically looks for paths doent work well

## How to Use

## Direct Analysis
1. Click **Open File**.
2. Select any binary file (even those that refuse to open in standard editors).
3. Switch between modes to instantly re-analyze the data.

### Notepad
1. Drag a file into notepad perferably windows 10 notepad since its way more lightweight and can handle big files without lag you can find it in "C:\Windows\notepad.exe"
2. Copy all of that what seems like useless code
3. Paste it all into the input box
4. The extraction will happen automatically.

## Use Cases
- **Malware Research**: Quickly identify RATs BTC Miners Loggers and hidden file paths.
- **Game Analysis**: Extract offsets, version numbers, and engine configurations.
- **Forensics**: Find hidden messages or developer comments within compiled code, or just cracking a software.

## Requirements
- Python 3.x
- No external libraries required (uses standard `tkinter` and `re`).
