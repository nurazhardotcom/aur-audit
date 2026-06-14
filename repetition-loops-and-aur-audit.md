# Engineering Diary: Taming LLM Repetition Loops & Building `aur-audit` for the AUR Security Incident

*By Nur Azhar — June 14, 2026*

In the landscape of agentic coding and security automation, we often run into two types of "infinite loops":
1. **Linguistic loops**: Where smaller models (like Gemini 3.5 Flash Low) get stuck repeating token sequences indefinitely.
2. **Execution loops**: Where system security tools fail to detect malicious persistence hooks running indefinitely on workstations.

This post dissects both: how to resolve attention-sink repetitions in local AI agents, and how we engineered `aur-audit` to scan PKGBUILD supply-chain attacks in real-time.

---

## Part 1: Why Smaller LLMs Loop (and How to Stop It)

While pair-programming system tools with agentic models, switching to lower-tier weights (like Gemini 3.5 Flash Low) is an excellent way to save API quota. However, smaller models frequently enter infinite loop states, endlessly echoing phrases (e.g. repeated notices about background environment resets).

### The Attention-Sink Mechanics
This happens due to how attention heads map sequence probabilities:
- **Attention Sinks**: In transformers, initial tokens or highly repeated tokens accumulate disproportionate attention weights. 
- **Context Pollution**: Once a phrase is printed twice, the model's auto-regressive probability of printing it a third time rises exponentially. Smaller models lack the parameterized complexity to "break out" of high-probability state sinks.

### Mitigating Repetition Sinks
1. **Prune Chat Context**: Periodically remove duplicate alerts or diagnostic notices from the prompt history. Clean context is the best defense.
2. **Temporary Scale-up**: If the model gets stuck, temporarily switch the model selection to a higher tier (like Gemini 3.5 Flash High) for a single turn. The higher parameter density breaks the probability loop, allowing you to return to the lower tier safely.
3. **Explicit Constraints**: Force system prompt instructions to forbid the echoing of previous status notes.

---

## Part 2: Building `aur-audit` & `aur-monitor`

With the active Arch User Repository (AUR) security incident of June 2026, malicious actors have been adopting abandoned packages and pushing modified install hooks. 

To combat this, we wrote `aur-audit` in **Clojure (Babashka)** to perform static analysis on downloaded packages prior to compilation, alongside `aur-monitor.clj` to act as a real-time threat monitor.

### Real-world Scan Results

Running our monitor against the 10 most recent updates on the AUR RSS feed yielded the following live threat report:

```bash
==========================================
    AUR Real-time Security Threat Monitor
==========================================
Fetching AUR updates RSS feed...
Identified 10 recent updates to audit.

=== Scanning Package: remotepower-server ===
[CRITICAL] NET-01 - Outbound network utilities or socket connections
  File:  remotepower-server.install : 7
  Match: "socket"
  Line:  1) Enable the CGI socket:

[CRITICAL] NET-01 - Outbound network utilities or socket connections
  File:  remotepower-server.install : 8
  Match: "socket"
  Line:  systemctl enable --now fcgiwrap.socket

[HIGH] PERS-01 - Attempts to establish persistence or enable system services
  File:  remotepower-server.install : 8
  Match: "systemctl enable"
  Line:  systemctl enable --now fcgiwrap.socket
```

### Analyzing the Findings (Triage & False Positives)
Our rules flagged `remotepower-server` and `remotepower-agent` for review:
- **`PERS-01` (Service Persistence)**: The install script runs `systemctl enable --now fcgiwrap.socket`. For a system daemon, this is standard, but the alert successfully forces the administrator to verify if `fcgiwrap` is indeed the intended service layer.
- **`NET-01` (False Positive)**: The word `socket` in the text comment `1) Enable the CGI socket:` triggered our network check. 

To reduce false positives in subsequent iterations, we will refine the rule regexes to ignore strings in commented lines (`#`) and separate network socket creation (`/dev/tcp`) from raw systemd configuration files (`.socket`).

---

## Conclusion
By combining **Clojure/Babashka** for near-instant system scripts and **Agentic AI** for high-speed design, we deployed a functional tool that audits our supply-chain dependencies in milliseconds. 

Check out the full repository and setup instructions at:
👉 **[github.com/nurazhardotcom/aur-audit](https://github.com/nurazhardotcom/aur-audit)**
