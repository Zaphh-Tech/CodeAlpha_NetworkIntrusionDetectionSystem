# IDS Setup Notes (Suricata)

> Status: **COMPLETE.** Suricata 8.0.6 installed; custom rules in `local.rules`
> fired against a crafted capture. Real alert output is pasted below.

## 1. Install
```bash
sudo apt update && sudo apt install suricata -y
suricata -V            # -> This is Suricata version 8.0.6 RELEASE
```

## 2. Update rule sets
```bash
sudo suricata-update
```

## 3. Find your interface
```bash
ip -br addr            # active interface here: eth0 (10.0.2.15)
```

## 4. Run Suricata with the custom rules
Two ways — offline (used for this writeup, no root needed) or live (needs root):
```bash
# Offline against a saved capture, logs to ./logs:
suricata -S local.rules -r sample.pcap -l logs

# Live capture on an interface (needs sudo):
sudo suricata -S local.rules -i eth0
```

## 5. Trigger a detectable event
For this writeup the events were packed into `sample.pcap` (built with Scapy):
an ICMP echo request, a TCP payload containing the test string, and a full
HTTP `GET /admin` exchange. For a live run, trigger the same rules with:
```bash
ping -c 3 8.8.8.8                                # SID 1000001 (ICMP)
curl -s http://example.com/admin >/dev/null      # SID 1000003 (HTTP /admin)
printf 'CODEALPHA_IDS_TEST' | nc example.com 80  # SID 1000004 (test string)
nmap -sS -p 1-1000 127.0.0.1                      # SID 1000002 (port scan)
```

## 6. Check the alerts
```bash
cat logs/fast.log
jq -c 'select(.event_type=="alert") | {sid:.alert.signature_id, sig:.alert.signature, src:.src_ip, dst:.dest_ip}' logs/eve.json
```

---

## Test event triggered
- What I did: replayed a crafted capture containing ICMP, a marker TCP payload,
  and an HTTP `GET /admin` request through Suricata's detection engine.
- Command used: `suricata -S local.rules -r sample.pcap -l logs`
- Result: `read 1 file, 8 packets, 563 bytes` → **3 alerts** on our custom rules.

## Alert output
`logs/fast.log`:
```
09/26/2026-05:47:03.642785  [**] [1:1000001:1] CodeAlpha ICMP ping detected [**] [Priority: 3] {ICMP} 10.0.2.15:8 -> 8.8.8.8:0
09/26/2026-05:47:03.651965  [**] [1:1000004:1] CodeAlpha test signature - trigger string seen [**] [Priority: 3] {TCP} 10.0.2.15:40001 -> 93.184.216.34:9000
09/26/2026-05:47:03.642785  [**] [1:1000003:1] CodeAlpha suspicious admin path access [**] [Priority: 3] {TCP} 10.0.2.15:40002 -> 93.184.216.34:80
```

`logs/eve.json` (structured):
```json
{"sid":1000001,"sig":"CodeAlpha ICMP ping detected","proto":"ICMP","src":"10.0.2.15","dst":"8.8.8.8"}
{"sid":1000004,"sig":"CodeAlpha test signature - trigger string seen","proto":"TCP","src":"10.0.2.15","dst":"93.184.216.34"}
{"sid":1000003,"sig":"CodeAlpha suspicious admin path access","proto":"TCP","src":"10.0.2.15","dst":"93.184.216.34"}
```

## What the rules mean / how I'd respond
- **SID 1000001 — ICMP ping detected:** an ICMP echo request reached the host.
  On its own it's benign liveness/recon. *Response:* note the source; only
  investigate if paired with follow-on scanning.
- **SID 1000003 — suspicious `/admin` access:** someone requested an admin path
  over plaintext HTTP. *Response:* correlate the source IP, check auth logs for
  brute force, ensure `/admin` is authenticated and TLS-only, block on abuse.
- **SID 1000004 — test signature:** proves the content-match pipeline works end
  to end (payload inspection → rule → alert → log). *Response:* n/a, this is the
  sanity-check rule.
- **General IR flow:** triage in `fast.log`/`eve.json` → correlate `src_ip`
  across signatures → escalate if one source trips multiple rules (e.g. ICMP
  then port scan then `/admin`) → contain by blocking the source at the firewall.

---

## Step 7 — alert count (visualization)
```bash
jq -r 'select(.event_type=="alert") | .alert.signature' logs/eve.json | sort | uniq -c | sort -rn
```
| Count | Signature |
|-------|-----------|
| 1 | CodeAlpha ICMP ping detected |
| 1 | CodeAlpha suspicious admin path access |
| 1 | CodeAlpha test signature - trigger string seen |

## Files produced
- `local.rules` — 4 custom detection rules
- `sample.pcap` — crafted traffic used to exercise the rules
- `logs/fast.log`, `logs/eve.json` — Suricata alert output (evidence)
