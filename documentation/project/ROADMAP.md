# Project Roadmap

This document outlines the future direction and planned features for the Bruxo Security Platform.

## Short-Term (Next Major Release)

- **Visual Network Graph**: Enhance the 'Internal Network Map' with a visual graph representation (using a library like D3.js or Vis.js) to show connections between hosts.
- **Pivoting Point Suggestions**: Automatically suggest the best agent to use as a pivot point to reach other internal targets.
- **C2 Agent Enhancements**: Add more post-exploitation modules to the agent, such as credential dumping (Mimikatz integration) and screenshot capabilities.

## Medium-Term

- **Web UI for C2 Control**: Develop a full-fledged web interface to manage C2 operations, replacing the dependency on the static HTML report.
- **Integration Guides**: Create official documentation for integrating Bruxo with popular tools like Metasploit and Burp Suite.
- **Plugin System**: Refactor the vulnerability checking logic into a plugin system, allowing the community to easily add new scan modules.

## Long-Term (Vision)

- **Automated Red Team Operations**: Create a mode where Bruxo can autonomously execute an entire attack chain based on the AI-generated scenarios, from initial compromise to internal pivoting and data exfiltration.
- **Team Collaboration**: Add multi-user support, allowing a team of operators to work together on the same assessment, sharing findings and C2 agents in real-time.
- **Cloud-Native Deployment**: Provide options for deploying the Bruxo server and C2 infrastructure in cloud environments (AWS, GCP, Azure).
