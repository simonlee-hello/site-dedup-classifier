package analyzer

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/simonlee-hello/site-dedup-classifier/pkg/fetcher"
	"github.com/simonlee-hello/site-dedup-classifier/pkg/parser"
	"github.com/simonlee-hello/site-dedup-classifier/pkg/rules"
	"github.com/simonlee-hello/site-dedup-classifier/pkg/types"
)

// SHA256Hex 计算 SHA256
func SHA256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// MatchesAnyPattern 匹配任意模式
func MatchesAnyPattern(text string, patterns []*regexp.Regexp) bool {
	if text == "" {
		return false
	}
	for _, p := range patterns {
		if p.MatchString(text) {
			return true
		}
	}
	return false
}

// DetectNoise 检测噪音站点
func DetectNoise(statusCode *int, bodyLength int, title string, bodyText string, responseText string, server string, rules *rules.CompiledRules) []string {
	var reasons []string

	titleCF := parser.NormalizeCaseFold(title)
	bodyCF := parser.NormalizeCaseFold(bodyText[:min(4000, len(bodyText))])
	responseCF := parser.NormalizeCaseFold(responseText[:min(4000, len(responseText))])
	serverCF := parser.NormalizeCaseFold(server)

	// 小体积网关错误页
	if statusCode != nil && rules.SmallGatewayStatuses[*statusCode] && bodyLength <= rules.SmallGatewayBodyLength {
		reasons = appendIfNotExists(reasons, types.NoiseReasonSmallGateway)
	}

	// 标题模式匹配
	if MatchesAnyPattern(titleCF, rules.NoiseTitlePatterns) {
		reasons = appendIfNotExists(reasons, types.NoiseReasonTitle)
	}

	// 正文模式匹配
	if MatchesAnyPattern(bodyCF, rules.NoiseBodyPatterns) {
		reasons = appendIfNotExists(reasons, types.NoiseReasonBody)
	}

	// 响应模式匹配
	if MatchesAnyPattern(responseCF, rules.NoiseResponsePatterns) {
		reasons = appendIfNotExists(reasons, types.NoiseReasonResponse)
	}

	// CDN/WAF 拦截
	if rules.CDNServers[serverCF] && statusCode != nil && rules.CDNStatuses[*statusCode] {
		for _, keyword := range rules.CDNKeywords {
			if strings.Contains(bodyCF, keyword) || strings.Contains(titleCF, keyword) {
				reasons = appendIfNotExists(reasons, types.NoiseReasonCDNBlock)
				break
			}
		}
	}

	sort.Strings(reasons)
	return reasons
}

// DetectDefaultPage 检测默认页面
func DetectDefaultPage(title string, bodyText string, rules *rules.CompiledRules) bool {
	titleCF := parser.NormalizeCaseFold(title)
	bodyCF := parser.NormalizeCaseFold(bodyText[:min(4000, len(bodyText))])
	for _, p := range rules.DefaultPagePatterns {
		if p.MatchString(titleCF) || p.MatchString(bodyCF) {
			return true
		}
	}
	return false
}

// ClassifyResponseShell 分类响应 Shell
func ClassifyResponseShell(statusCode *int, contentType string, title string, bodyText string, lowInformation bool, rules *rules.CompiledRules) (string, string) {
	titleCF := parser.NormalizeCaseFold(title)
	bodyCF := parser.NormalizeCaseFold(bodyText)
	contentTypeBase := fetcher.GetBaseContentType(contentType)

	// 维护页
	if MatchesAnyPattern(titleCF, rules.MaintenanceTitlePatterns) || MatchesAnyPattern(bodyCF, rules.MaintenanceBodyPatterns) {
		return "maintenance_shell", types.NoiseReasonMaintenance
	}

	// 统一认证 API 响应
	if rules.AuthContentTypes[contentType] && MatchesAnyPattern(bodyCF, rules.AuthTextPatterns) {
		return "auth_api_shell", "命中统一认证/API未登录响应页"
	}

	// 结构化 Shell 候选
	structuredShellCandidate := lowInformation && (types.StructuredXMLContentTypes[contentTypeBase] || types.StructuredJSONContentTypes[contentTypeBase])

	// 拒绝访问 Shell
	if (statusCode != nil && rules.DenyStatuses[*statusCode] || structuredShellCandidate) && MatchesAnyPattern(bodyCF, rules.DenyTextPatterns) {
		return "deny_shell", "命中统一拒绝访问响应页"
	}

	// 低信息量 Shell
	if lowInformation {
		return "low_information_shell", "命中低信息量响应页"
	}

	return "", ""
}

// DetectAuthShell 检测认证 Shell
func DetectAuthShell(title string, bodyText string, finalURL string, formActions []string, links []string, rules *rules.CompiledRules) bool {
	parts := []string{}
	if title != "" {
		parts = append(parts, title)
	}
	if len(bodyText) > 1200 {
		parts = append(parts, bodyText[:min(1200, len(bodyText))])
	} else if bodyText != "" {
		parts = append(parts, bodyText)
	}
	if finalURL != "" {
		parts = append(parts, finalURL)
	}
	if len(formActions) > 0 {
		parts = append(parts, strings.Join(parser.SortStringSlice(formActions), " "))
	}
	if len(links) > 0 {
		parts = append(parts, strings.Join(parser.SortStringSlice(links), " "))
	}

	joined := strings.Join(parts, " ")
	if joined == "" {
		return false
	}

	hits := 0
	for _, p := range rules.AuthShellPatterns {
		if p.MatchString(joined) {
			hits++
		}
	}
	return hits >= 2
}

// DetectLowInformation 检测低信息量页面
func DetectLowInformation(bodyLength int, bodyText string, nonIconResourceCount int, resources []string, rules *rules.CompiledRules) bool {
	if bodyLength < rules.LowInfoBodyLength && !BodyHasBusinessText(bodyText, rules) {
		return true
	}
	if nonIconResourceCount == 0 {
		return true
	}
	nonIconResources := parser.FilterNonIconResources(resources)
	return len(nonIconResources) < rules.LowInfoMinNonIconResources
}

// BodyHasBusinessText 检查是否有业务文本
func BodyHasBusinessText(text string, rules *rules.CompiledRules) bool {
	if text == "" {
		return false
	}
	return rules.BusinessTextPattern.MatchString(text)
}

// ResolveHostIPs 解析主机 IP
func ResolveHostIPs(host string, port int) []string {
	ips := make(map[string]struct{})
	addr := fmt.Sprintf("%s:%d", host, port)
	addrs, err := net.LookupHost(host)
	if err != nil {
		return nil
	}
	for _, a := range addrs {
		ips[a] = struct{}{}
	}
	_ = addr
	result := make([]string, 0, len(ips))
	for ip := range ips {
		result = append(result, ip)
	}
	sort.Strings(result)
	return result
}

// BuildHeaderSignature 构建 Header 签名
func BuildHeaderSignature(headers map[string]string) []interface{} {
	normalized := make(map[string]string)
	for k, v := range headers {
		normalized[strings.ToLower(k)] = parser.NormalizeText(v)
	}
	etag := normalized["etag"]
	lastModified := normalized["last-modified"]
	server := strings.ToLower(normalized["server"])
	powered := strings.ToLower(normalized["x-powered-by"])
	contentType := strings.ToLower(strings.SplitN(normalized["content-type"], ";", 2)[0])
	contentType = strings.TrimSpace(contentType)

	if etag != "" || lastModified != "" {
		return []interface{}{"strong", etag, lastModified, server, powered, contentType}
	}
	if server != "" || powered != "" || contentType != "" {
		return []interface{}{"weak", server, powered, contentType}
	}
	return nil
}

// BuildRedirectSignature 构建重定向签名
func BuildRedirectSignature(siteURL string, finalURL string, originalStatus *int) []interface{} {
	siteNorm := parser.NormalizeURLForCompare(siteURL)
	finalNorm := parser.NormalizeURLForCompare(finalURL)
	if finalURL == "" {
		finalNorm = siteNorm
	}
	if originalStatus != nil && *originalStatus >= 300 && *originalStatus < 400 && finalNorm != siteNorm {
		return []interface{}{"redirect", finalNorm}
	}
	return []interface{}{"direct"}
}

// BuildStructureSignature 构建结构签名
func BuildStructureSignature(title string, metaDesc string, metaKeywords string, metaGenerator string, metaViewport string) []interface{} {
	fields := []string{
		parser.NormalizeCaseFold(title),
		parser.NormalizeCaseFold(metaDesc),
		parser.NormalizeCaseFold(metaKeywords),
		parser.NormalizeCaseFold(metaGenerator),
		parser.NormalizeCaseFold(metaViewport),
	}
	hasNonEmpty := false
	for _, f := range fields {
		if f != "" {
			hasNonEmpty = true
			break
		}
	}
	if !hasNonEmpty {
		return nil
	}
	result := make([]interface{}, len(fields))
	for i, f := range fields {
		result[i] = f
	}
	return result
}

// BuildKeyPathSignature 构建关键路径签名
func BuildKeyPathSignature(probes []types.PathProbe) []interface{} {
	sorted := make([]types.PathProbe, len(probes))
	copy(sorted, probes)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Path < sorted[j].Path
	})
	result := make([]interface{}, len(sorted))
	for i, p := range sorted {
		// 解引用指针以获取实际值
		var statusCode interface{}
		if p.StatusCode != nil {
			statusCode = *p.StatusCode
		}
		result[i] = []interface{}{p.Path, statusCode, p.BodySHA256, p.ContentType, p.ETag, p.LastModified}
	}
	return result
}

// NormalizeShellFieldName 归一化 Shell 字段名
func NormalizeShellFieldName(name string) string {
	re := regexp.MustCompile(`[^a-z0-9]+`)
	return re.ReplaceAllString(strings.ToLower(name), "")
}

// NormalizeShellScalar 归一化 Shell 标量值
func NormalizeShellScalar(value interface{}) string {
	switch v := value.(type) {
	case bool:
		if v {
			return "true"
		}
		return "false"
	case nil:
		return "null"
	default:
		return parser.NormalizeCaseFold(fmt.Sprintf("%v", v))
	}
}

// HasExactShellSignals 检查是否有精确 Shell 信号
func HasExactShellSignals(analysis *types.SiteAnalysis) bool {
	return analysis.ShellType != "" &&
		analysis.FinalStatus != nil &&
		analysis.ContentType != "" &&
		analysis.BodySHA256 != "" &&
		len(analysis.KeyPathSignature) > 0
}

// AnalyzeSite 分析单个站点
func AnalyzeSite(site types.SiteInput, timeout float64, insecure bool, rules *rules.CompiledRules) *types.SiteAnalysis {
	analysis := &types.SiteAnalysis{
		Site: site,
	}

	// 解析 IP
	analysis.ResolvedIPs = ResolveHostIPs(site.Host, site.Port)

	// 第一次请求（不跟随重定向）
	firstResult, err := fetcher.FetchURL(site.URL, fetcher.FetchOptions{
		AllowRedirects: false,
		Timeout:        time.Duration(timeout * float64(time.Second)),
		Insecure:       insecure,
		MaxBodyBytes:   rules.MaxBodyBytes,
		UserAgent:      rules.UserAgent,
		UseEnvProxy:    rules.UseEnvProxy,
	})
	if err != nil {
		analysis.ProbeError = err.Error()
		return analysis
	}

	// 处理第一次响应
	firstHeaders := firstResult.Headers
	analysis.OriginalStatus = &firstResult.StatusCode
	redirectTarget := firstHeaders["location"]
	if redirectTarget != "" {
		analysis.RedirectTarget = parser.NormalizeRedirectTarget(redirectTarget, firstResult.FinalURL)
	}

	var finalResult *fetcher.FetchResult
	if redirectTarget != "" && firstResult.StatusCode >= 300 && firstResult.StatusCode < 400 {
		// 跟随重定向
		finalResult, err = fetcher.FetchURL(site.URL, fetcher.FetchOptions{
			AllowRedirects: true,
			Timeout:        time.Duration(timeout * float64(time.Second)),
			Insecure:       insecure,
			MaxBodyBytes:   rules.MaxBodyBytes,
			UserAgent:      rules.UserAgent,
			UseEnvProxy:    rules.UseEnvProxy,
		})
		if err != nil {
			analysis.ProbeError = err.Error()
			return analysis
		}
	} else {
		finalResult = firstResult
	}

	// 处理最终响应
	analysis.FinalStatus = &finalResult.StatusCode
	analysis.FinalURL = finalResult.FinalURL
	analysis.FinalURLNormalized = parser.NormalizeURLForCompare(finalResult.FinalURL)
	if analysis.FinalURL == "" {
		analysis.FinalURL = site.URL
		analysis.FinalURLNormalized = parser.NormalizeURLForCompare(site.URL)
	}
	analysis.FinalOrigin = parser.CanonicalOrigin(analysis.FinalURL)
	analysis.BodyLength = len(finalResult.Body)
	analysis.BodySHA256 = SHA256Hex(finalResult.Body)
	analysis.ETag = finalResult.Headers["etag"]
	analysis.LastModified = finalResult.Headers["last-modified"]
	analysis.Server = finalResult.Headers["server"]
	analysis.XPoweredBy = finalResult.Headers["x-powered-by"]
	ct := finalResult.Headers["content-type"]
	analysis.ContentType = strings.ToLower(strings.TrimSpace(strings.SplitN(ct, ";", 2)[0]))

	// 响应文本
	responseText := parser.NormalizeText(string(finalResult.Body))
	if len(responseText) > 4000 {
		responseText = responseText[:min(4000, len(responseText))]
	}
	analysis.ResponseTextExcerpt = responseText

	// HTML 解析
	var bodyText string
	var formActions []string
	var links []string
	isHTML := analysis.ContentType == "text/html" || analysis.ContentType == "application/xhtml+xml"
	if !isHTML {
		sample := strings.ToLower(strings.TrimSpace(string(finalResult.Body[:min(512, len(finalResult.Body))])))
		isHTML = strings.HasPrefix(sample, "<!doctype html") || strings.HasPrefix(sample, "<html")
	}

	if isHTML {
		htmlResult := parser.ParseHTML(analysis.FinalURL, finalResult.Body)
		analysis.Title = htmlResult.Title
		analysis.MetaDescription = htmlResult.MetaDescription
		analysis.MetaKeywords = htmlResult.MetaKeywords
		analysis.MetaGenerator = htmlResult.MetaGenerator
		analysis.MetaViewport = htmlResult.MetaViewport
		analysis.Resources = htmlResult.Resources
		analysis.NonIconResourceCount = htmlResult.NonIconResourceCount
		formActions = htmlResult.FormActions
		links = htmlResult.Links
		bodyText = htmlResult.BodyText
	} else {
		bodyText = responseText
	}

	if len(bodyText) > 4000 {
		analysis.BodyTextExcerpt = bodyText[:min(4000, len(bodyText))]
	} else {
		analysis.BodyTextExcerpt = bodyText
	}

	// 噪音检测
	analysis.NoiseReasons = DetectNoise(
		analysis.FinalStatus,
		analysis.BodyLength,
		analysis.Title,
		bodyText,
		responseText,
		analysis.Server,
		rules,
	)

	// 默认页面检测
	analysis.DefaultPageHit = DetectDefaultPage(analysis.Title, bodyText, rules)

	// 低信息量检测
	analysis.LowInformation = DetectLowInformation(
		analysis.BodyLength,
		bodyText,
		analysis.NonIconResourceCount,
		analysis.Resources,
		rules,
	)
	if analysis.DefaultPageHit {
		analysis.LowInformation = true
	}

	// 认证 Shell 检测
	analysis.AuthShellLike = DetectAuthShell(
		analysis.Title,
		bodyText,
		analysis.FinalURLNormalized,
		formActions,
		links,
		rules,
	)

	// 响应 Shell 分类
	analysis.ShellType, analysis.ShellReason = ClassifyResponseShell(
		analysis.FinalStatus,
		analysis.ContentType,
		analysis.Title,
		responseText,
		analysis.LowInformation,
		rules,
	)
	if analysis.ShellType == "maintenance_shell" {
		analysis.NoiseReasons = appendIfNotExists(analysis.NoiseReasons, types.NoiseReasonMaintenance)
		sort.Strings(analysis.NoiseReasons)
	}

	// 探测关键路径
	analysis.KeyPaths = ProbeKeyPaths(site, timeout, insecure, rules)

	// 构建签名
	analysis.HeaderSignature = BuildHeaderSignature(finalResult.Headers)
	analysis.RedirectSignature = BuildRedirectSignature(site.URL, analysis.FinalURL, analysis.OriginalStatus)
	analysis.StructureSignature = BuildStructureSignature(
		analysis.Title,
		analysis.MetaDescription,
		analysis.MetaKeywords,
		analysis.MetaGenerator,
		analysis.MetaViewport,
	)
	analysis.ResourceSignature = make([]interface{}, len(analysis.Resources))
	for i, r := range analysis.Resources {
		analysis.ResourceSignature[i] = r
	}
	analysis.KeyPathSignature = BuildKeyPathSignature(analysis.KeyPaths)

	// 判断是否准备好比较
	analysis.ComparisonReady = len(analysis.HeaderSignature) > 0 &&
		len(analysis.RedirectSignature) > 0 &&
		len(analysis.StructureSignature) > 0 &&
		len(analysis.ResourceSignature) > 0 &&
		len(analysis.KeyPathSignature) > 0

	// 构建等价指纹
	if analysis.ComparisonReady {
		analysis.EquivalenceFingerprint = []interface{}{
			analysis.HeaderSignature,
			analysis.RedirectSignature,
			analysis.StructureSignature,
			analysis.ResourceSignature,
			analysis.KeyPathSignature,
		}
	}

	// 构建 Shell 指纹
	if HasExactShellSignals(analysis) {
		// 解引用指针以获取实际值
		var statusCode interface{}
		if analysis.FinalStatus != nil {
			statusCode = *analysis.FinalStatus
		}
		analysis.ShellExactFingerprint = []interface{}{
			analysis.ShellType,
			statusCode,
			analysis.ContentType,
			analysis.BodySHA256,
			analysis.KeyPathSignature,
		}
		analysis.ShellMergeFingerprint = BuildShellMergeFingerprint(analysis)
	}

	return analysis
}

// ProbeKeyPaths 探测关键路径
func ProbeKeyPaths(site types.SiteInput, timeout float64, insecure bool, rules *rules.CompiledRules) []types.PathProbe {
	origin := strings.TrimRight(site.URL, "/")
	results := make([]types.PathProbe, 0, len(rules.KeyPaths))

	for _, path := range rules.KeyPaths {
		probeURL := origin + path
		result, err := fetcher.FetchURL(probeURL, fetcher.FetchOptions{
			AllowRedirects: true,
			Timeout:        time.Duration(timeout * float64(time.Second)),
			Insecure:       insecure,
			MaxBodyBytes:   rules.MaxBodyBytes,
			UserAgent:      rules.UserAgent,
			UseEnvProxy:    rules.UseEnvProxy,
		})
		if err != nil {
			results = append(results, types.PathProbe{
				Path:  path,
				Error: err.Error(),
			})
			continue
		}

		ct := fetcher.GetBaseContentType(result.Headers["content-type"])
		bodyText := string(result.Body)
		mergeSig := BuildStructuredPayloadSignature(ct, bodyText)

		statusCode := result.StatusCode
		results = append(results, types.PathProbe{
			Path:           path,
			StatusCode:     &statusCode,
			BodySHA256:     SHA256Hex(result.Body),
			ContentType:    ct,
			ETag:           result.Headers["etag"],
			LastModified:   result.Headers["last-modified"],
			MergeSignature: mergeSig,
		})
	}

	return results
}

// BuildStructuredPayloadSignature 构建结构化 Payload 签名
func BuildStructuredPayloadSignature(contentType string, bodyText string) []interface{} {
	if bodyText == "" {
		return nil
	}
	ct := fetcher.GetBaseContentType(contentType)
	if types.StructuredJSONContentTypes[ct] {
		// JSON 解析
		items := collectJSONFields(bodyText)
		if len(items) == 0 {
			return nil
		}
		sort.Slice(items, func(i, j int) bool {
			return items[i][0] < items[j][0]
		})
		result := make([]interface{}, len(items))
		for i, item := range items {
			result[i] = []interface{}{item[0], item[1]}
		}
		return []interface{}{"json", result}
	}
	if types.StructuredXMLContentTypes[ct] {
		// XML 解析
		items := collectXMLFields(bodyText)
		if len(items) == 0 {
			return nil
		}
		sort.Slice(items, func(i, j int) bool {
			return items[i][0] < items[j][0]
		})
		result := make([]interface{}, len(items))
		for i, item := range items {
			result[i] = []interface{}{item[0], item[1]}
		}
		// 获取根元素名
		rootName := getXMLRootName(bodyText)
		return []interface{}{"xml", rootName, result}
	}
	return nil
}

// getXMLRootName 获取 XML 根元素名
func getXMLRootName(bodyText string) string {
	decoder := xml.NewDecoder(strings.NewReader(bodyText))
	for {
		token, err := decoder.Token()
		if err != nil {
			return ""
		}
		switch t := token.(type) {
		case xml.StartElement:
			return NormalizeShellFieldName(t.Name.Local)
		}
	}
}

// collectXMLFields 收集 XML 字段
func collectXMLFields(bodyText string) [][2]string {
	var items [][2]string
	decoder := xml.NewDecoder(strings.NewReader(bodyText))
	var path []string

	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}
		switch t := token.(type) {
		case xml.StartElement:
			localName := NormalizeShellFieldName(t.Name.Local)
			path = append(path, localName)
		case xml.EndElement:
			if len(path) > 0 {
				path = path[:len(path)-1]
			}
		case xml.CharData:
			text := parser.NormalizeCaseFold(string(t))
			if text != "" && len(path) > 0 {
				leaf := path[len(path)-1]
				if types.SemanticShellFieldNames[leaf] {
					fullPath := strings.Join(path, ".")
					items = append(items, [2]string{fullPath, text})
				}
			}
		}
	}
	return items
}

// collectJSONFields 收集 JSON 字段
func collectJSONFields(bodyText string) [][2]string {
	// 简化的 JSON 字段收集，实际实现需要解析 JSON
	var items [][2]string
	// 这里需要实现 JSON 解析逻辑
	return items
}

// BuildShellMergeFingerprint 构建 Shell 合并指纹
func BuildShellMergeFingerprint(analysis *types.SiteAnalysis) []interface{} {
	if len(analysis.ShellExactFingerprint) == 0 {
		return nil
	}
	if analysis.ShellType != "deny_shell" && analysis.ShellType != "auth_api_shell" {
		return analysis.ShellExactFingerprint
	}

	payloadSignature := BuildStructuredPayloadSignature(analysis.ContentType, analysis.ResponseTextExcerpt)
	if len(payloadSignature) == 0 {
		payloadSignature = []interface{}{"raw_sha256", analysis.BodySHA256}
	}
	keyPathSignature := buildShellMergeKeyPathSignature(analysis.KeyPaths)

	// 解引用指针以获取实际值
	var statusCode interface{}
	if analysis.FinalStatus != nil {
		statusCode = *analysis.FinalStatus
	}

	return []interface{}{
		analysis.ShellType,
		statusCode,
		analysis.ContentType,
		parser.NormalizeCaseFold(analysis.Server),
		payloadSignature,
		keyPathSignature,
	}
}

// buildShellMergeKeyPathSignature 构建 Shell 合并关键路径签名
func buildShellMergeKeyPathSignature(probes []types.PathProbe) []interface{} {
	sorted := make([]types.PathProbe, len(probes))
	copy(sorted, probes)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Path < sorted[j].Path
	})
	result := make([]interface{}, len(sorted))
	for i, p := range sorted {
		mergeSig := p.MergeSignature
		if len(mergeSig) == 0 {
			mergeSig = []interface{}{p.BodySHA256}
		}
		// 解引用指针以获取实际值
		var statusCode interface{}
		if p.StatusCode != nil {
			statusCode = *p.StatusCode
		}
		result[i] = []interface{}{p.Path, statusCode, p.ContentType, mergeSig, p.Error}
	}
	return result
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func appendIfNotExists(slice []string, item string) []string {
	for _, s := range slice {
		if s == item {
			return slice
		}
	}
	return append(slice, item)
}
