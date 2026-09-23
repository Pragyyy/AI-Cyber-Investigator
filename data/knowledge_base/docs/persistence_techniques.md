# Common Windows Persistence Techniques

## Why attackers set up persistence
A one-time compromise is fragile - a reboot, logoff, or password change can lose the
attacker's access. Persistence mechanisms let malicious code run again automatically,
without the attacker needing to re-exploit anything.

## The most common mechanisms in Windows environments
- **Scheduled tasks** (schtasks /create): runs a program on a schedule or trigger such
  as "at logon". Easy to create, easy to overlook among legitimate scheduled jobs.
- **Registry Run keys**: adding an entry so a program launches at every logon; simple
  and widely used by both legitimate software and malware.
- **New local accounts**: creating an account (net user ... /add) gives the attacker a
  standing way back in that does not depend on any specific vulnerability.
- **Windows services** (sc create): services can run with high privileges and start
  automatically at boot, making them attractive despite requiring administrative rights
  to create.

## What raises suspicion
The mechanism itself is often legitimate administrative activity; what matters is the
target. A scheduled task or service pointing at an executable in C:\Users\Public,
a temp folder, or a path with no digital signature is far more concerning than one
pointing at a recognized, signed program in Program Files.
