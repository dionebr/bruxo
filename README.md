# 🧙 Bruxo - High-Performance Web Directory Scanner

**Bruxo** is a command-line web directory scanner (fuzzer) written in Go and optimized for extreme speed. It combines a high-concurrency request engine with a clean user interface and interactive reports to provide a professional pentesting experience.

The project was focused on surpassing the benchmarks of established tools, utilizing the `fasthttp` library to minimize memory allocation and maximize requests per second.

---

## 🚀 Key Features

- ⚡ **Extreme Performance**: Built with `fasthttp` to achieve hundreds of requests per second, optimized for low latency and minimal memory consumption.
- 📊 **Interactive HTML Report**: Generates a modern dashboard with a doughnut chart (using Chart.js) that summarizes the distribution of found status codes.
- 🤖 **AI Analysis (Optional)**: Integrate with the Groq API (using the Llama 3.1 model) to get security insights for each found result. Just set up your API key.
- 🎨 **Professional CLI Interface**:
    - A presentation banner with the project's visual identity.
    - A clear and aligned configuration panel.
    - A real-time progress bar with stats (RPS, Completed, Found).
    - A formatted summary table for easy reading.
- ⚙️ **Advanced Filtering and Options**:
    - **Add Extensions (`-x`)**: Add extensions like `.php`, `.html` to each word from the wordlist.
    - **Exclusion Filter (`-fx`)**: Ignore paths containing common keywords (e.g., `css`, `js`, `png`).
    - **Hidden Content Detection (`-hidden`)**: Finds pages that return the same status code as the "not found" page but with different content.

---

## 🛠️ Installation & Usage

### 1. Compiling from source

Make sure you have Go installed. To compile Bruxo, run:

```bash
go build -o bruxo bruxo.go
```

### 2. AI Analysis (Optional)

To use the AI analysis feature, you need an API key from [Groq](https://console.groq.com/keys). Export the key as an environment variable:

```bash
export GROQ_API_KEY="your_key_here"
```

### 3. Running a Scan

Execute the compiled program with your desired parameters.

**Simple Example:**
```bash
./bruxo -u http://example.com -w /path/to/your/wordlist.txt
```

**Advanced Example (more threads, extensions, and an HTML report):**
```bash
./bruxo -u http://example.com/admin -w /usr/share/seclists/Discovery/Web-Content/common.txt -t 500 -x .php,.bak -o report.html
```

---

## ⚙️ Command-Line Parameters

| Flag      | Default                                         | Description                                                                 |
|-----------|-------------------------------------------------|-----------------------------------------------------------------------------|
| `-u`        | (required)                                      | Target URL for the scan.                                                    |
| `-w`        | (required)                                      | Path to the wordlist.                                                       |
| `-t`        | 200                                             | Number of concurrent threads.                                               |
| `-o`        | ""                                              | Output file for the report (supports `.html`).                               |
| `-sc`       | "200,204,301,302,307,403,500"                   | Status codes to show, comma-separated.                                      |
| `-fc`       | "404"                                           | Status codes to filter (not show), comma-separated.                         |
| `-fx`       | "css,js,png,jpg,jpeg,svg,ico,woff,woff2,eot,ttf" | Extensions or keywords to ignore in paths, comma-separated.                 |
| `-x`        | ""                                              | Extensions to add to each wordlist entry (e.g., `.php,.html`).              |
| `-rl`       | 1000                                            | Requests per second limit.                                                  |
| `-timeout`  | 10                                              | Request timeout in seconds.                                                 |
| `-hidden`   | true                                            | Enables hidden content detection by response body difference.               |
| `-v`        | false                                           | Verbose mode.                                                               |
| `-debug`    | false                                           | Debug mode.                                                                 |

## Disclaimer
Tool for **educational purposes** and **authorized testing** only.  
Unauthorized use is **illegal**. The developers are not responsible for misuse.  

---

## Support
Open an **issue** on the official repository.
