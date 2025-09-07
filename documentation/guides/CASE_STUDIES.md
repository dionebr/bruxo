# Case Studies

> This section is a placeholder for future content.

This section will feature real-world (anonymized) case studies demonstrating how Bruxo was used in security assessments to identify and exploit complex vulnerability chains.

### Case Study 1: E-Commerce Platform Compromise

- **Objective**: Gain access to customer database.
- **Initial Finding**: Exposed `.git` directory on a subdomain.
- **Attack Chain**:
  1. Used Bruxo to find the exposed repository.
  2. Manually dumped the source code.
  3. Found hardcoded AWS credentials in a configuration file.
  4. Used credentials to access an S3 bucket containing database backups.

### Case Study 2: Internal Network Pivot

- **Objective**: Achieve Domain Admin on the internal network.
- **Initial Finding**: SQL Injection on the public-facing web application.
- **Attack Chain**:
  1. Exploited SQLi to get a shell on the web server.
  2. Deployed the Bruxo C2 agent.
  3. Used the `internal_scan` command to map the local subnet.
  4. Identified an unpatched Domain Controller.
  5. Used C2 to download exploit tools and compromise the DC.
