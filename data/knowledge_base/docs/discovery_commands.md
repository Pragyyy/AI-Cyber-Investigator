# Discovery Commands: Normal Admin Work vs. Early-Stage Attack

## The overlap problem
Commands like whoami, net user, ipconfig /all, and systeminfo are used constantly by
legitimate system administrators, which makes them a weak signal in isolation. The
same commands are also almost always among the first things an attacker runs after
gaining a foothold, to understand what access they have and what the environment
looks like.

## What shifts the balance toward suspicious
Context is what separates the two cases, not the commands themselves:
- Discovery commands running within minutes of a login that itself looked unusual
  (came right after a brute-force success, or from an external/rarely-used source).
- Several different discovery commands run back-to-back in a short window, rather than
  a single command run occasionally over the course of normal work.
- Discovery commands followed by persistence or lateral-movement activity, which
  confirms the account was being used to explore rather than to do routine work.

## Practical guidance
Do not treat a lone whoami or ipconfig as an incident by itself. Correlate it with the
login that preceded it and the activity that followed it before drawing a conclusion.
