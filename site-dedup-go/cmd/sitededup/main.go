package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/simonlee-hello/site-dedup-classifier/pkg/analyzer"
	"github.com/simonlee-hello/site-dedup-classifier/pkg/output"
	"github.com/simonlee-hello/site-dedup-classifier/pkg/parser"
	"github.com/simonlee-hello/site-dedup-classifier/pkg/rules"
	"github.com/simonlee-hello/site-dedup-classifier/pkg/types"
)

func main() {
	// 命令行参数
	filePath := flag.String("f", "", "输入文件，一行一个站点")
	outputPath := flag.String("o", "", "可选，输出完整 JSON 结果文件")
	rulesPath := flag.String("rules", "", "规则文件路径")
	timeout := flag.Float64("timeout", 0, "HTTP 超时时间")
	workers := flag.Int("workers", 8, "并发数")
	insecure := flag.Bool("insecure", false, "关闭 HTTPS 证书校验")
	verifyTLS := flag.Bool("verify-tls", false, "开启 HTTPS 证书校验")
	retries := flag.Int("retries", -1, "失败后的重试次数")
	userAgent := flag.String("user-agent", "", "覆盖默认请求 User-Agent")
	useEnvProxy := flag.Bool("use-env-proxy", false, "启用环境变量中的代理设置")
	details := flag.Bool("details", false, "将完整 JSON 结果直接打印到 stdout")
	sampleLimit := flag.Int("sample-limit", 5, "概要输出每类最多展示多少条")
	noProgress := flag.Bool("no-progress", false, "关闭进度展示")

	flag.Parse()

	// 验证必填参数
	if *filePath == "" {
		fmt.Fprintln(os.Stderr, "错误: 必须指定输入文件 (-f)")
		os.Exit(1)
	}

	// 确定规则文件路径
	if *rulesPath == "" {
		ex, err := os.Executable()
		if err == nil {
			*rulesPath = filepath.Join(filepath.Dir(ex), types.RulesFileName)
		}
		if _, err := os.Stat(*rulesPath); os.IsNotExist(err) {
			// 尝试当前目录
			*rulesPath = types.RulesFileName
		}
	}

	// 加载规则
	rulesConfig, err := rules.LoadRules(*rulesPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "加载规则失败: %v\n", err)
		os.Exit(1)
	}

	// 覆盖规则
	if *retries >= 0 {
		rulesConfig.RetryAttempts = *retries
	}
	if *userAgent != "" {
		rulesConfig.UserAgent = *userAgent
	}
	if *verifyTLS {
		rulesConfig.VerifyTLS = true
	} else if *insecure {
		rulesConfig.VerifyTLS = false
	}
	if *useEnvProxy {
		rulesConfig.UseEnvProxy = true
	}

	// 加载站点
	sites, err := loadSites(*filePath, rulesConfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "加载输入失败: %v\n", err)
		os.Exit(1)
	}
	if len(sites) == 0 {
		fmt.Fprintln(os.Stderr, "输入文件中没有可用站点")
		os.Exit(1)
	}

	// 设置超时
	actualTimeout := rulesConfig.DefaultTimeout
	if *timeout > 0 {
		actualTimeout = *timeout
	}

	// 设置并发数
	actualWorkers := *workers
	if actualWorkers < 1 {
		actualWorkers = 1
	}
	if actualWorkers > len(sites) {
		actualWorkers = len(sites)
	}

	// 分析站点
	startTime := time.Now()
	analyses := analyzeSites(sites, actualTimeout, !rulesConfig.VerifyTLS, actualWorkers, !*noProgress, rulesConfig)
	elapsed := time.Since(startTime)

	// 构建输出
	result := output.BuildOutput(analyses, nil)
	result.Summary["使用并发数"] = actualWorkers
	result.Summary["任务耗时秒"] = elapsed.Seconds()
	result.Summary["任务耗时"] = output.FormatDuration(elapsed.Seconds())

	// 保存 JSON
	if *outputPath != "" {
		if err := output.SaveJSON(*outputPath, result); err != nil {
			fmt.Fprintf(os.Stderr, "保存 JSON 失败: %v\n", err)
			os.Exit(1)
		}
	}

	// 输出结果
	if *details {
		output.WriteJSON(os.Stdout, result)
	} else {
		output.PrintSummaryReportPlain(result, *sampleLimit)
		if *outputPath != "" {
			fmt.Println()
			fmt.Printf("完整 JSON 结果已写入: %s\n", *outputPath)
			fmt.Printf("规则文件: %s\n", *rulesPath)
		}
	}
}

func loadSites(path string, rulesConfig *rules.CompiledRules) ([]types.SiteInput, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var sites []types.SiteInput
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(f)
	lineNumber := 0

	for scanner.Scan() {
		lineNumber++
		raw := scanner.Text()
		site, err := parseSiteLine(raw, rulesConfig)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, lineNumber, err)
		}
		if site == nil {
			continue
		}
		if seen[site.URL] {
			continue
		}
		seen[site.URL] = true
		sites = append(sites, *site)
	}

	return sites, scanner.Err()
}

func parseSiteLine(raw string, rulesConfig *rules.CompiledRules) (*types.SiteInput, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.HasPrefix(raw, "#") {
		return nil, nil
	}

	url, scheme, host, port, err := parser.NormalizeSiteURL(raw, rulesConfig)
	if err != nil {
		return nil, err
	}

	isIP := parser.IPLiteral(host)
	regDomain := parser.GetRegistrableDomain(host, rulesConfig)

	return &types.SiteInput{
		Raw:               raw,
		URL:               url,
		Scheme:            scheme,
		Host:              host,
		Port:              port,
		IsIP:              isIP,
		RegistrableDomain: regDomain,
	}, nil
}

func analyzeSites(sites []types.SiteInput, timeout float64, insecure bool, workers int, showProgress bool, rulesConfig *rules.CompiledRules) map[string]*types.SiteAnalysis {
	analyses := make(map[string]*types.SiteAnalysis)
	total := len(sites)
	done := 0
	failed := 0
	var mu sync.Mutex
	var wg sync.WaitGroup

	if showProgress {
		renderProgress(done, total, failed)
	}

	// 创建工作队列
	jobs := make(chan types.SiteInput, workers)
	results := make(chan *types.SiteAnalysis, workers)

	// 启动 worker
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for site := range jobs {
				analysis := analyzer.AnalyzeSite(site, timeout, insecure, rulesConfig)
				results <- analysis
			}
		}()
	}

	// 发送任务
	go func() {
		for _, site := range sites {
			jobs <- site
		}
		close(jobs)
	}()

	// 收集结果
	go func() {
		wg.Wait()
		close(results)
	}()

	for analysis := range results {
		mu.Lock()
		analyses[analysis.Site.URL] = analysis
		done++
		if analysis.ProbeError != "" {
			failed++
		}
		if showProgress {
			renderProgress(done, total, failed)
		}
		mu.Unlock()
	}

	return analyses
}

func renderProgress(done, total, failed int) {
	if total <= 0 {
		return
	}
	percent := float64(done) * 100.0 / float64(total)
	ok := done - failed
	fmt.Fprintf(os.Stderr, "\r进度: %d/%d (%5.1f%%) | 成功: %d | 失败: %d", done, total, percent, ok, failed)
	if done == total {
		fmt.Fprintln(os.Stderr)
	}
}

func init() {
	// 设置默认规则路径
	runtime.GOMAXPROCS(runtime.NumCPU())
}
