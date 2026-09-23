# Investigating Suspicious PowerShell Activity

## Why PowerShell is a favorite attacker tool
PowerShell ships on every modern Windows system, is trusted by most security tools by
default, and can execute code entirely in memory without writing a file to disk. This
makes it attractive for attackers who want to avoid dropping an easily-detected
executable.

## Indicators worth investigating together, not alone
No single flag proves malicious intent, but the following in combination are a strong
signal: an encoded command (-EncodedCommand / -enc with a long base64 string), a hidden
window (-WindowStyle Hidden), an execution-policy bypass (-ExecutionPolicy Bypass), and
a parent process that is an Office application (winword.exe, excel.exe, outlook.exe)
rather than a normal interactive shell. A single hidden-window flag on its own is
common in legitimate automation and is not by itself suspicious.

## What to check next
- Decode any base64 command to see what it actually runs.
- Identify the parent process and, if it is an Office document, treat this as a likely
  phishing or macro-based initial access rather than an isolated PowerShell event.
- Look for any network connection or file write that follows the PowerShell execution,
  since PowerShell is usually a means to a further end (downloading a tool, contacting
  a command-and-control server, creating persistence).
