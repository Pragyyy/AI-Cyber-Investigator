# Recognizing Command-and-Control Beaconing

## The pattern
Malware that maintains contact with an attacker-controlled server ("command and
control", or C2) often does so on a timer, checking in every fixed number of seconds
or minutes to fetch new instructions. Seen in network logs, this produces outbound
connections to the same external address at near-regular intervals - unlike normal
human browsing, which is bursty and irregular.

## What makes it more suspicious
- The connection uses a port not typically associated with the protocol claimed, or a
  port historically associated with offensive tooling (4444 is a very common default
  for exploitation frameworks).
- The connecting process is a scripting engine (PowerShell, cmd.exe) or an executable
  from an unusual location (a user's temp or public folder) rather than a browser.
- The destination has no other legitimate business relationship with the organization.

## Investigative next steps
- Note the exact interval between connections; a low variance strongly supports
  beaconing rather than coincidence.
- Check what happened on the host immediately before the first connection - it is
  usually the initial compromise or the point a downloaded payload executed.
- Block the destination address and isolate the host from the network pending review.
