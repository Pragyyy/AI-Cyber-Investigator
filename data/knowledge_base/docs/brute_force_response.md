# Responding to Brute-Force Login Activity

## What it looks like
A burst of failed authentication attempts against one account, arriving faster than a
human typing mistakes would explain - typically many attempts within a few minutes,
from the same source IP address. The activity may target one account (password
guessing) or many accounts from the same source (credential stuffing / spraying).

## Why a successful login afterward matters
If a successful authentication follows the failed attempts from the same source, this
is a strong signal that the brute force succeeded rather than simply being blocked or
abandoned. The gap between the last failure and the success is worth noting: a gap of
seconds to a couple of minutes is consistent with an automated tool finding the right
password; a much longer gap may indicate a coincidental legitimate login instead.

## Recommended response actions
- Disable or force a password reset on the targeted account immediately.
- Block or rate-limit the source IP at the firewall or identity provider.
- Review what the account did immediately after the successful login, since that is
  the attacker's actual objective, not the brute force itself.
- Enable or verify multi-factor authentication on the account going forward.
- Check whether the same source IP targeted any other accounts in the same time window.
