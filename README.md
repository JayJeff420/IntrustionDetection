# Intrusion Detection System (IDS)

## Overview

This repository implements a modular Intrusion Detection System (IDS) designed for live packet capture, signature-based detection, and basic behavioral analytics. The design emphasizes extensibility, observability, and operational safety. Components are modular so they can be adapted for high-throughput deployments, forensic replay, or research prototypes.

Key components:

* **Sensor**: Captures network packets (using `scapy`) and extracts metadata.
* **Analyzer**: Matches packet metadata against a rule set (signature engine) and performs behavioral detection (stateful counters, rate-based heuristics).
* **Signature Engine**: Loads and evaluates a rich rule language (JSON format) supporting header, payload, and stateful matchers.
* **Alerter**: Deduplicates and persists alerts to a log file and prints alerts to the console.
* **Responder**: Maintains an in-memory blocklist and can be extended to perform system-level blocking (iptables, firewall rules).
* **DBManager**: Persists connections and alerts to an SQLite database for analysis and auditing.
* **CentralConsole**: Orchestrates components and provides lifecycle control (start/stop, configuration).

This README documents installation, operation, the rule language, examples, and development notes.

---

## Table of Contents

1. [Requirements](#requirements)
2. [Installation](#installation)
3. [Repository Structure](#repository-structure)
4. [Quick Start — Live Capture](#quick-start--live-capture)
5. [Rule Language (signatures.json)](#rule-language-signaturesjson)
6. [Examples of Rules](#examples-of-rules)
7. [Operational Safety and Notes](#operational-safety-and-notes)
8. [Extending the System](#extending-the-system)
9. [Testing and Validation](#testing-and-validation)
10. [Next Steps and Recommendations](#next-steps-and-recommendations)

---

## Requirements

* Python 3.8 or later
* Root / elevated privileges to capture live packets (Linux/macOS: `sudo` often required)
* Python packages:

  * `scapy`
  * (optional) `pyahocorasick` for high-performance substring scanning

Install Python dependencies in a virtual environment when possible.

---

## Installation

1. Clone or copy repository files to a working directory.

2. Create a virtual environment and install dependencies:

```bash
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install scapy
# optional for fast substring matching
# pip install pyahocorasick
```

3. Ensure `signatures.json` is present in the working directory and contains valid rules.

---

## Repository Structure

```
/ (project root)
├─ ids_live.py                # main live-capture IDS program
├─ signatures.json           # rule file (rich rule language)
├─ alerts.log                # generated alert log file (runtime)
├─ ids_live.db               # SQLite database (generated at runtime)
├─ README.md                 # this file
└─ utils/                    # optional helpers (rule compiler, tests, pcap replay)
```

---

## Quick Start — Live Capture

**Important:** Run on an isolated test network or with care on production networks.

Example command:

```bash
sudo python3 ids_live.py --iface eth0 --filter "ip"
```

Options:

* `--iface`: network interface name (e.g., `eth0`, `wlan0`); omit to allow scapy to pick a default.
* `--filter`: BPF filter string (e.g., `"tcp and port 80"`) to reduce captured traffic.
* `--sigs`: path to signature JSON file (default: `signatures.json`).

Behavior:

* Packets are captured by `Sensor`, parsed, and converted to structured metadata.
* `Analyzer` logs connections to the database and executes signature matching.
* `Alerter` prints unique alerts to stdout and appends them to `alerts.log`.
* `Responder` records blocked IPs (in-memory) and prints blocked IPs at shutdown.

Stop the process with `Ctrl+C`. The console will gracefully stop the sensor thread, close the database, and show blocked IPs.

---

## Rule Language (`signatures.json`)

The rule language is a JSON-based declarative schema designed for expressiveness and operational control. Rules include static (packet-level) matching as well as stateful (windowed) counters.

### Top-level rule fields

* `id` (string) — Unique rule identifier.
* `description` (string) — Human-readable description.
* `enabled` (boolean, default `true`) — Whether the rule is active.
* `priority` (integer, default `100`) — Evaluation order; lower values evaluated first.
* `severity` (`info`|`low`|`medium`|`high`|`critical`) — For triage.
* `match` (object) — A boolean expression describing conditions. See match primitives below.
* `stateful` (object, optional) — Parameters for sliding-window counters and thresholds.
* `action` (`alert`|`block`|`count`|`drop`|`notify`) — Action to take on match.
* `scope` (object, optional) — Limit rule applicability (interfaces, VLANs).
* `whitelist` (object, optional) — Exceptions preventing action or alerting.
* `expires_at` (ISO8601 string, optional) — Expiration timestamp.
* `tags` (array) — List of tag strings.
* `dry_run` (boolean) — If `true`, do not execute destructive actions; only alert/log.

### Match primitives

`match` supports logical composition of primitive conditions using `all`, `any`, and `not`.

Primitive matchers include:

* `protocol`: `"TCP"`, `"UDP"`, `"ICMP"`, or numeric protocol value.
* `port`: `{ "src": 1234 }`, `{ "dst": 80 }`, `{ "dst_range": [1000, 2000] }`.
* `ip`: `{ "src": "1.2.3.0/24" }`, `{ "dst": "10.0.0.5" }`.
* `tcp_flags`: `{ "syn": true, "ack": false }` (fields: `syn`, `ack`, `fin`, `rst`, `psh`, `urg`, `ece`, `cwr`).
* `payload_contains`: substring case-insensitive match on textual payload.
* `payload_regex`: compiled regular expression applied to payload.
* `payload_bytes`: raw byte sequence (hex string) matched against packet payload.
* `length`: `{ "gt": 1000, "lt": 1500 }` to match packet or payload length ranges.
* `http`: structured HTTP header/line match: `{ "header": "User-Agent", "regex": "BadScanner" }`.
* `dns`: DNS query name or type match: `{ "qname_regex": "\\.danger\\.com$" }`.
* `exists`: presence of a parsed field (e.g., `"http"`).

### Logical composition

Examples:

* `{"all": [matcher1, matcher2]}`
* `{"any": [matcher1, matcher2]}`
* `{"not": matcher}`

### Stateful counters

Stateful rules provide sliding-window counters keyed by one or more packet attributes.

Stateful fields:

* `key_by`: array of fields to key counters (e.g., `["src_ip"]`, `["src_ip","dest_port"]`).
* `window`: integer seconds for sliding window.
* `threshold`: integer threshold value.
* `compare`: comparison operator string, one of `">"`, `">="`, `"<"`, `"=="`.
* `unit`: `packets` | `bytes` | `flows` | `connections`.
* `suppress_for`: optional seconds to suppress repeated alerts for the same key.

When a stateful rule matches and its counter exceeds the configured threshold according to `compare`, the configured `action` is executed. Suppression prevents alert storms by enforcing a cooldown per `(rule_id, key)`.

---

## Examples of Rules

A set of representative rules is included in `signatures.json`. The following demonstrates the capabilities of the language.

1. **SYN Flood (stateful)**

```json
{
  "id": "RULE_TCP_SYN_FLOOD",
  "description": "Detect lots of TCP SYNs without ACKs per source IP",
  "match": { "all": [ { "protocol": "TCP" }, { "tcp_flags": { "syn": true, "ack": false } } ] },
  "stateful": { "key_by": ["src_ip"], "window": 60, "threshold": 500, "compare": ">" },
  "action": "block",
  "severity": "high"
}
```

2. **SSH Brute Force (stateful flows)**

```json
{
  "id": "RULE_SSH_BRUTE_FORCE",
  "description": "Multiple connection attempts to SSH port 22 within 5 minutes",
  "match": { "all": [ { "protocol": "TCP" }, { "port": { "dst": 22 } } ] },
  "stateful": { "key_by": ["src_ip"], "window": 300, "threshold": 50, "unit": "flows", "compare": ">" },
  "action": "alert",
  "severity": "medium"
}
```

3. **HTTP Bad User-Agent (dry-run alert)**

```json
{
  "id": "RULE_HTTP_BAD_UA",
  "description": "HTTP requests with suspicious user-agent header",
  "match": { "all": [ { "protocol": "TCP" }, { "http": { "header": "User-Agent", "regex": "BadScanner|Curl/.*lib" } } ] },
  "action": "alert",
  "dry_run": true,
  "severity": "low"
}
```

4. **Payload Byte Marker (critical)**

```json
{
  "id": "RULE_PAYLOAD_HEUR_MALWARE",
  "description": "Payload contains malware marker bytes",
  "match": { "any": [ { "payload_contains": "malware-signature" }, { "payload_bytes": { "hex": "4d5a9000" } } ] },
  "action": "block",
  "severity": "critical"
}
```

---

## Operational Safety and Notes

* **Run on test networks where possible.** Live packet capture and automatic blocking can impact connectivity and operations.
* **Root privileges required** to capture packets on most systems when using `scapy`.
* **Blocking is in-memory by default.** The `Responder` class currently maintains a memory blocklist. System-level firewall changes (e.g., `iptables`) must be implemented deliberately and can be enabled with a safe, idempotent routine and explicit confirmation or `dry_run` support.
* **False positives** can occur. Use `dry_run` and `suppress_for` to limit disruptions during rule tuning.
* **Logging**: alerts are written to `alerts.log` and connections/alerts persisted to `ids_live.db`.

---

## Extending the System

Suggested implementation improvements and extensions:

1. **High-throughput design**: introduce a packet metadata queue (e.g., `queue.Queue`) and a pool of worker threads to perform rule matching asynchronously.
2. **Aho–Corasick substring engine**: use `pyahocorasick` to scan many simple substrings in a single pass for performance.
3. **Firewall integration**: implement `Responder` methods for safe, idempotent firewall operations with a `commit` and `dry_run` mode.
4. **Rule management API**: build a REST interface for safe enabling/disabling of rules, and a web UI for rule editing, versioning, and dry-run testing.
5. **ML anomaly detection**: add a parallel detection pipeline that computes feature vectors (packet size distributions, protocol ratios, inter-arrival times) and uses unsupervised models (isolation forest, autoencoder) to propose anomalous hosts.
6. **SIEM integration**: forward alerts to syslog, Elasticsearch, or a SIEM for correlation and long-term storage.

---

## Testing and Validation

**Unit tests**:

* Validate each match primitive (tcp_flags, payload regex, payload_bytes, length, ports).
* Assert `stateful` counters behave correctly across windows and keys.

**Integration tests**:

* Replay PCAP files with `scapy.utils.rdpcap()` and assert expected alerts and DB entries.

**Performance tests**:

* Measure packet handling latency and drop rate under large PCAP replay or on high-traffic interfaces.
* Benchmark substring scanning approaches and regex application strategies.

---

## Next Steps and Recommendations

1. Implement a production-ready `SignatureEngine` that performs rule validation, pre-compiles regexes, converts hex strings to `bytes`, and normalizes IPs/ports using the `ipaddress` module.
2. Add a worker queue for packet processing, and tune the `dos_threshold_per_minute` and `suppress_for` defaults based on baseline traffic metrics from your environment.
3. Maintain a `rules` Git repository and enforce a change-review process for rule changes to avoid accidental disruptive rules in production.
4. Consider combining signature detection with ML-based anomaly detection to reduce false positives.

---

## License and Attribution

This project is provided as a reference prototype for IDS design and is intended for educational and development use. It is not production hardened. Use and modify under terms of your organization or personal discretion.



For questions, further enhancements (firewall integration, ML detector, Aho–Corasick optimization, hot-reload rule API), or to generate unit tests and sample PCAPs, request the specific feature and it will be implemented.
