# Frequently Asked Questions (FAQ)

### Q1: Is Bruxo legal to use?
**A:** Yes, provided you use it legally and ethically. Bruxo is a tool for security professionals to conduct **authorized** security assessments. Using it on systems without explicit permission is illegal. See our [Security Policy](../project/SECURITY.md).

### Q2: Why do I need a Groq API key?
**A:** The API key is only required for AI-powered features, specifically the Attack Scenario generation and the Social Engineering campaign generation. The core scanner and C2 framework will function without it.

### Q3: Can the C2 agent be detected by antivirus (AV) software?
**A:** It's possible. The agent is a simple Go binary and is not obfuscated or packed. Advanced EDR and AV solutions may flag it based on its behavior (e.g., making periodic web requests, executing shell commands). For real-world engagements, consider using packers or custom loaders.

### Q4: How can I make the internal network scan faster?
**A:** The scan speed is limited by network latency and the number of ports being checked. You can modify the `ports` slice and the `concurrency` variable in the `handleInternalScan` function within `agent/main.go` to adjust its behavior before compiling.
