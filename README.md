# CodeAlpha_NetworkIntrusionDetectionSystem

A small intrusion detection setup using Suricata, built for Task 4 of the CodeAlpha
Cyber Security internship.

I wrote a few custom detection rules, ran Suricata against some test traffic, and
wrote down which alerts fired, what they mean, and how I'd respond to them.

## What's in here

- `local.rules` — my custom detection rules
- `sample.pcap` — the traffic I tested the rules against
- `logs/` — the alerts Suricata produced (`fast.log` and `eve.json`)
- `notes.md` — setup steps, the alert output, and my response notes

## Running it

```bash
# against the saved capture
suricata -S local.rules -r sample.pcap -l logs
cat logs/fast.log

# or live on an interface
sudo suricata -S local.rules -i eth0
```

## What it caught

Three of my rules fired against the test traffic: an ICMP ping, an HTTP request to an
`/admin` path, and a custom payload signature. The full alert output and how I'd
handle each one is in `notes.md`.
