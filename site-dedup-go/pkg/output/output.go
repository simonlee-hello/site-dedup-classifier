package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/tophant/site-dedup-go/pkg/fetcher"
	"github.com/tophant/site-dedup-go/pkg/merger"
	"github.com/tophant/site-dedup-go/pkg/types"
)

// BuildOutput 构建输出结果
func BuildOutput(analyses map[string]*types.SiteAnalysis, externalGroups []types.MergeGroup) *types.OutputResult {
	result := &types.OutputResult{
		Summary:          make(map[string]interface{}),
		FailureSummary:   make([]types.FailureSummaryItem, 0),
		NoiseSites:       make([]types.NoiseSiteItem, 0),
		MergeGroups:      make([]types.MergeGroupItem, 0),
		IndependentSites: make([]types.IndependentSiteItem, 0),
		Details:          make(map[string]interface{}),
	}

	// 噪音原因映射
	noiseReasonMap := make(map[string]map[string]bool)
	for url, analysis := range analyses {
		if len(analysis.NoiseReasons) > 0 {
			noiseReasonMap[url] = make(map[string]bool)
			for _, r := range analysis.NoiseReasons {
				noiseReasonMap[url][r] = true
			}
		}
	}

	// Shell 候选 URL
	shellCandidateURLs := make(map[string]bool)
	for url, analysis := range analyses {
		if analysis.ProbeError == "" && noiseReasonMap[url] == nil {
			shellCandidateURLs[url] = true
		}
	}

	// 收集同 host Shell 结果
	sameHostShellGroups, sameHostShellNoise, sameHostShellConsumed := merger.CollectSameHostShellResults(analyses, shellCandidateURLs)
	for url, reasons := range sameHostShellNoise {
		if noiseReasonMap[url] == nil {
			noiseReasonMap[url] = make(map[string]bool)
		}
		for _, r := range reasons {
			noiseReasonMap[url][r] = true
		}
	}

	// 收集同端口子域 Shell 结果
	samePortShellCandidateURLs := make(map[string]bool)
	for url := range shellCandidateURLs {
		if !sameHostShellConsumed[url] && noiseReasonMap[url] == nil {
			samePortShellCandidateURLs[url] = true
		}
	}
	samePortShellGroups, samePortShellConsumed := merger.CollectSamePortSubdomainShellResults(analyses, samePortShellCandidateURLs)

	shellConsumedURLs := make(map[string]bool)
	for u := range sameHostShellConsumed {
		shellConsumedURLs[u] = true
	}
	for u := range samePortShellConsumed {
		shellConsumedURLs[u] = true
	}

	// 活跃 URL
	activeURLs := make(map[string]bool)
	for url := range analyses {
		if !shellConsumedURLs[url] && noiseReasonMap[url] == nil {
			activeURLs[url] = true
		}
	}

	// 并查集合并
	uf := merger.NewUnionFind(mapKeys(activeURLs))
	merger.CollectRedirectMerges(analyses, activeURLs, uf, &externalGroups)
	merger.CollectEquivalentMerges(analyses, activeURLs, uf)

	// 构建合并组
	var mergeGroups []types.MergeGroup
	groupedURLs := make(map[string]bool)
	mergeGroups = append(mergeGroups, sameHostShellGroups...)
	mergeGroups = append(mergeGroups, samePortShellGroups...)
	for _, group := range append(sameHostShellGroups, samePortShellGroups...) {
		for _, u := range group.Members {
			groupedURLs[u] = true
		}
	}

	// 处理并查集分组
	for _, urls := range uf.Groups() {
		if len(urls) < 2 {
			continue
		}
		representative := merger.ChooseRepresentative(urls, analyses)
		hosts := make(map[string]bool)
		for _, u := range urls {
			hosts[analyses[u].Site.Host] = true
		}
		hasRedirectEdge := false
		for _, u := range urls {
			if u == representative {
				continue
			}
			a := analyses[u]
			if len(a.RedirectSignature) > 0 && a.RedirectSignature[0] == "redirect" {
				if len(a.RedirectSignature) > 1 && a.RedirectSignature[1] == normalizeURLForCompare(representative) {
					hasRedirectEdge = true
					break
				}
			}
		}

		var groupType, reason string
		if hasRedirectEdge && len(urls) == 2 && len(hosts) == 1 {
			groupType = types.GroupTypeHTTPHTTPS
			reason = types.MergeReasonHTTPHTTPS
		} else if len(hosts) == 1 {
			groupType = types.GroupTypeSameHost
			if hasRedirectEdge {
				reason = types.MergeReasonSameHostWithRedirect
			} else {
				reason = types.MergeReasonSameHost
			}
		} else {
			regDomains := make(map[string]bool)
			for _, u := range urls {
				if analyses[u].Site.RegistrableDomain != nil {
					regDomains[*analyses[u].Site.RegistrableDomain] = true
				}
			}
			if len(regDomains) > 1 {
				groupType = types.GroupTypeSameIPCrossDomain
				reason = types.MergeReasonSameIPCrossDomain
			} else {
				groupType = types.GroupTypeSameDomain
				reason = types.MergeReasonSameDomain
			}
		}

		mergeGroups = append(mergeGroups, types.MergeGroup{
			GroupType:      groupType,
			Representative: representative,
			Members:        sort.StringSlice(urls),
			Reason:         reason,
		})
		for _, u := range urls {
			groupedURLs[u] = true
		}
	}

	// 添加外部组
	mergeGroups = append(mergeGroups, externalGroups...)
	for _, group := range externalGroups {
		for _, u := range group.Members {
			groupedURLs[u] = true
		}
	}

	// 分类结果
	var noiseSites []types.NoiseSiteItem
	var independentSites []types.IndependentSiteItem
	failureCategories := make(map[string][]string)

	for url, analysis := range analyses {
		combinedNoiseReasons := sortedKeys(noiseReasonMap[url])

		if len(combinedNoiseReasons) > 0 {
			noiseSites = append(noiseSites, types.NoiseSiteItem{
				URL:        url,
				Reasons:    combinedNoiseReasons,
				Title:      analysis.Title,
				StatusCode: analysis.FinalStatus,
			})
			continue
		}
		if groupedURLs[url] {
			continue
		}

		reason := types.IndependentReasonDefault
		if analysis.ProbeError != "" {
			reason = types.IndependentReasonProbeFailed
		} else if analysis.Site.IsIP {
			reason = types.IndependentReasonIPDirect
		} else if analysis.LowInformation {
			reason = types.IndependentReasonLowInfo
		} else if analysis.AuthShellLike {
			reason = types.IndependentReasonAuthShell
		} else if !analysis.ComparisonReady {
			reason = types.IndependentReasonSignalsWeak
		}

		independentSites = append(independentSites, types.IndependentSiteItem{
			URL:        url,
			Reason:     reason,
			Title:      analysis.Title,
			StatusCode: analysis.FinalStatus,
		})
	}

	// 构建详情
	for url, analysis := range analyses {
		combinedNoiseReasons := sortedKeys(noiseReasonMap[url])
		if analysis.ProbeError != "" {
			category := fetcher.ClassifyProbeError(analysis.ProbeError)
			failureCategories[category] = append(failureCategories[category], url)
		}
		result.Details[url] = map[string]interface{}{
			"raw":                 analysis.Site.Raw,
			"probe_error":         analysis.ProbeError,
			"original_status":     analysis.OriginalStatus,
			"final_status":        analysis.FinalStatus,
			"final_url":           analysis.FinalURLNormalized,
			"title":               analysis.Title,
			"meta_description":    analysis.MetaDescription,
			"meta_keywords":       analysis.MetaKeywords,
			"meta_generator":      analysis.MetaGenerator,
			"meta_viewport":       analysis.MetaViewport,
			"server":              analysis.Server,
			"etag":                analysis.ETag,
			"last_modified":       analysis.LastModified,
			"content_type":        analysis.ContentType,
			"body_length":         analysis.BodyLength,
			"body_sha256":         analysis.BodySHA256,
			"body_text_excerpt":   analysis.BodyTextExcerpt,
			"response_text_excerpt": analysis.ResponseTextExcerpt,
			"resources":           analysis.Resources,
			"noise_reasons":       combinedNoiseReasons,
			"default_page_hit":    analysis.DefaultPageHit,
			"low_information":     analysis.LowInformation,
			"auth_shell_like":     analysis.AuthShellLike,
			"shell_type":          analysis.ShellType,
			"shell_reason":        analysis.ShellReason,
			"resolved_ips":        analysis.ResolvedIPs,
			"comparison_ready":    analysis.ComparisonReady,
			"key_paths":           analysis.KeyPaths,
		}
	}

	// 统计
	mergeMemberCount := 0
	for _, g := range mergeGroups {
		mergeMemberCount += len(g.Members)
	}
	probeFailedCount := 0
	for _, a := range analyses {
		if a.ProbeError != "" {
			probeFailedCount++
		}
	}

	// 失败原因概要
	var failureSummary []types.FailureSummaryItem
	for category, urls := range failureCategories {
		sampleURLs := make([]string, len(urls))
		copy(sampleURLs, urls)
		sort.Strings(sampleURLs)
		if len(sampleURLs) > 5 {
			sampleURLs = sampleURLs[:5]
		}
		failureSummary = append(failureSummary, types.FailureSummaryItem{
			Category:   category,
			Count:      len(urls),
			SampleURLs: sampleURLs,
		})
	}
	sort.Slice(failureSummary, func(i, j int) bool {
		if failureSummary[i].Count != failureSummary[j].Count {
			return failureSummary[i].Count > failureSummary[j].Count
		}
		return failureSummary[i].Category < failureSummary[j].Category
	})

	// 排序噪音站点
	sort.Slice(noiseSites, func(i, j int) bool {
		return noiseSites[i].URL < noiseSites[j].URL
	})

	// 排序合并组
	sort.Slice(mergeGroups, func(i, j int) bool {
		if mergeGroups[i].GroupType != mergeGroups[j].GroupType {
			return mergeGroups[i].GroupType < mergeGroups[j].GroupType
		}
		return mergeGroups[i].Representative < mergeGroups[j].Representative
	})

	// 排序独立站点
	sort.Slice(independentSites, func(i, j int) bool {
		return independentSites[i].URL < independentSites[j].URL
	})

	// 转换合并组
	mergeGroupItems := make([]types.MergeGroupItem, len(mergeGroups))
	for i, g := range mergeGroups {
		mergeGroupItems[i] = types.MergeGroupItem{
			GroupType:      g.GroupType,
			Representative: g.Representative,
			MemberCount:    len(g.Members),
			Members:        g.Members,
			Reason:         g.Reason,
		}
	}

	result.Summary["输入站点数"] = len(analyses)
	result.Summary["探测失败数"] = probeFailedCount
	result.Summary["噪音站点数"] = len(noiseSites)
	result.Summary["可合并站点组数"] = len(mergeGroups)
	result.Summary["可合并站点成员数"] = mergeMemberCount
	result.Summary["独立站点数"] = len(independentSites)
	result.FailureSummary = failureSummary
	result.NoiseSites = noiseSites
	result.MergeGroups = mergeGroupItems
	result.IndependentSites = independentSites

	return result
}

func normalizeURLForCompare(urlStr string) string {
	// 简化版，完整版在 parser 包中
	return urlStr
}

func mapKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func sortedKeys(m map[string]bool) []string {
	if m == nil {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// FormatDuration 格式化时间
func FormatDuration(seconds float64) string {
	totalMS := int(seconds * 1000)
	hours := totalMS / (3600 * 1000)
	totalMS %= 3600 * 1000
	minutes := totalMS / (60 * 1000)
	totalMS %= 60 * 1000
	secs := totalMS / 1000
	millis := totalMS % 1000

	if hours > 0 {
		return fmt.Sprintf("%d小时%d分%d秒", hours, minutes, secs)
	}
	if minutes > 0 {
		return fmt.Sprintf("%d分%d秒", minutes, secs)
	}
	if secs > 0 {
		return fmt.Sprintf("%d.%03d秒", secs, millis)
	}
	return fmt.Sprintf("%d毫秒", millis)
}

// PrintSummaryReportPlain 打印纯文本报告
func PrintSummaryReportPlain(result *types.OutputResult, sampleLimit int) {
	summary := result.Summary

	fmt.Println("结果概要")
	fmt.Printf("- 输入站点数: %v\n", summary["输入站点数"])
	fmt.Printf("- 使用并发数: %v\n", summary["使用并发数"])
	fmt.Printf("- 任务耗时: %v\n", summary["任务耗时"])
	fmt.Printf("- 探测失败数: %v\n", summary["探测失败数"])
	fmt.Printf("- 噪音站点数: %v\n", summary["噪音站点数"])
	fmt.Printf("- 可合并站点组数: %v\n", summary["可合并站点组数"])
	fmt.Printf("- 可合并站点成员数: %v\n", summary["可合并站点成员数"])
	fmt.Printf("- 独立站点数: %v\n", summary["独立站点数"])
	fmt.Println()

	fmt.Println("失败原因概要")
	if len(result.FailureSummary) == 0 {
		fmt.Println("- 无")
	} else {
		for i, item := range result.FailureSummary {
			if i >= sampleLimit {
				fmt.Printf("- 其余 %d 类失败原因省略\n", len(result.FailureSummary)-sampleLimit)
				break
			}
			samples := shortenURLs(item.SampleURLs, sampleLimit)
			fmt.Printf("- %s: %d 个\n", item.Category, item.Count)
			fmt.Printf("  示例: %s\n", samples)
		}
	}
	fmt.Println()

	fmt.Println("噪音站点示例")
	if len(result.NoiseSites) == 0 {
		fmt.Println("- 无")
	} else {
		for i, item := range result.NoiseSites {
			if i >= sampleLimit {
				fmt.Printf("- 其余 %d 个噪音站点省略\n", len(result.NoiseSites)-sampleLimit)
				break
			}
			reasons := strings.Join(item.Reasons, "；")
			statusCode := "-"
			if item.StatusCode != nil {
				statusCode = fmt.Sprintf("%d", *item.StatusCode)
			}
			fmt.Printf("- %s [%s] %s\n", item.URL, statusCode, reasons)
		}
	}
	fmt.Println()

	fmt.Println("可合并站点组概要")
	if len(result.MergeGroups) == 0 {
		fmt.Println("- 无")
	} else {
		for i, group := range result.MergeGroups {
			if i >= sampleLimit {
				fmt.Printf("- 其余 %d 个合并组省略\n", len(result.MergeGroups)-sampleLimit)
				break
			}
			samples := shortenURLs(group.Members, sampleLimit)
			fmt.Printf("- 类型: %s\n", group.GroupType)
			fmt.Printf("  代表站点: %s\n", group.Representative)
			fmt.Printf("  成员数: %d\n", group.MemberCount)
			fmt.Printf("  成员示例: %s\n", samples)
			fmt.Printf("  原因: %s\n", group.Reason)
		}
	}
	fmt.Println()

	fmt.Println("独立站点示例")
	if len(result.IndependentSites) == 0 {
		fmt.Println("- 无")
	} else {
		for i, item := range result.IndependentSites {
			if i >= sampleLimit {
				fmt.Printf("- 其余 %d 个独立站点省略\n", len(result.IndependentSites)-sampleLimit)
				break
			}
			statusCode := "-"
			if item.StatusCode != nil {
				statusCode = fmt.Sprintf("%d", *item.StatusCode)
			}
			fmt.Printf("- %s [%s] %s\n", item.URL, statusCode, item.Reason)
		}
	}
}

func shortenURLs(urls []string, limit int) string {
	if len(urls) == 0 {
		return "无"
	}
	if len(urls) <= limit {
		return strings.Join(urls, "，")
	}
	head := strings.Join(urls[:limit], "，")
	return fmt.Sprintf("%s ...（其余 %d 个省略）", head, len(urls)-limit)
}

// WriteJSON 输出 JSON
func WriteJSON(w io.Writer, result *types.OutputResult) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	return encoder.Encode(result)
}

// SaveJSON 保存 JSON 到文件
func SaveJSON(path string, result *types.OutputResult) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return WriteJSON(f, result)
}
