package merger

import (
	"fmt"
	"sort"
	"strings"

	neturl "net/url"

	"github.com/tophant/site-dedup-go/pkg/types"
)

// ChooseRepresentative 选择代表站点
func ChooseRepresentative(urls []string, analyses map[string]*types.SiteAnalysis) string {
	if len(urls) == 0 {
		return ""
	}

	best := urls[0]
	bestScore := scoreURL(urls[0], analyses)

	for _, url := range urls[1:] {
		s := scoreURL(url, analyses)
		if compareScore(s, bestScore) < 0 {
			best = url
			bestScore = s
		}
	}
	return best
}

func scoreURL(url string, analyses map[string]*types.SiteAnalysis) [5]interface{} {
	analysis := analyses[url]
	redirectRank := 0
	if len(analysis.RedirectSignature) > 0 && analysis.RedirectSignature[0] == "redirect" {
		redirectRank = 1
	}
	httpsRank := 0
	if analysis.Site.Scheme != "https" {
		httpsRank = 1
	}
	portRank := 0
	if analysis.Site.Port != 443 {
		portRank = 1
	}
	ipRank := 0
	if analysis.Site.IsIP {
		ipRank = 1
	}
	return [5]interface{}{redirectRank, httpsRank, portRank, ipRank, url}
}

func compareScore(a, b [5]interface{}) int {
	for i := 0; i < 4; i++ {
		ai := a[i].(int)
		bi := b[i].(int)
		if ai < bi {
			return -1
		}
		if ai > bi {
			return 1
		}
	}
	as := a[4].(string)
	bs := b[4].(string)
	if as < bs {
		return -1
	}
	if as > bs {
		return 1
	}
	return 0
}

// GroupByFingerprint 按指纹分组
func GroupByFingerprint(urls []string, analyses map[string]*types.SiteAnalysis) map[string][]string {
	grouped := make(map[string][]string)
	for _, url := range urls {
		analysis := analyses[url]
		if len(analysis.EquivalenceFingerprint) == 0 {
			continue
		}
		key := fingerprintKey(analysis.EquivalenceFingerprint)
		grouped[key] = append(grouped[key], url)
	}
	return grouped
}

func fingerprintKey(fp []interface{}) string {
	// 将指纹转换为字符串键
	return fmt.Sprintf("%v", fp)
}

// CollectRedirectMerges 收集重定向合并
func CollectRedirectMerges(analyses map[string]*types.SiteAnalysis, activeURLs map[string]bool, uf *UnionFind, externalGroups *[]types.MergeGroup) {
	byURL := make(map[string]bool)
	for url := range analyses {
		byURL[url] = true
	}

	for siteURL, analysis := range analyses {
		if !activeURLs[siteURL] {
			continue
		}
		if len(analysis.NoiseReasons) > 0 || analysis.ProbeError != "" {
			continue
		}
		if analysis.OriginalStatus == nil || *analysis.OriginalStatus < 300 || *analysis.OriginalStatus >= 400 {
			continue
		}
		if analysis.RedirectTarget == "" {
			continue
		}

		source, _ := neturl.Parse(siteURL)
		target, _ := neturl.Parse(analysis.RedirectTarget)
		if source == nil || target == nil {
			continue
		}
		if source.Scheme != "http" || target.Scheme != "https" {
			continue
		}
		if source.Hostname() != target.Hostname() {
			continue
		}

		if byURL[analysis.RedirectTarget] && activeURLs[analysis.RedirectTarget] {
			uf.Union(siteURL, analysis.RedirectTarget)
		} else {
			*externalGroups = append(*externalGroups, types.MergeGroup{
				GroupType:      types.GroupTypeHTTPHTTPS,
				Representative: analysis.RedirectTarget,
				Members:        []string{siteURL},
				Reason:         types.MergeReasonHTTPHTTPS,
			})
			delete(activeURLs, siteURL)
		}
	}
}

// CollectEquivalentMerges 收集等价合并
func CollectEquivalentMerges(analyses map[string]*types.SiteAnalysis, activeURLs map[string]bool, uf *UnionFind) {
	// 按 host 分组
	byHost := make(map[string][]string)
	for url := range activeURLs {
		analysis := analyses[url]
		if len(analysis.NoiseReasons) > 0 || analysis.ProbeError != "" || analysis.AuthShellLike || !analysis.ComparisonReady || analysis.ShellType != "" {
			continue
		}
		byHost[analysis.Site.Host] = append(byHost[analysis.Site.Host], url)
	}

	for _, urls := range byHost {
		if len(urls) < 2 {
			continue
		}
		for _, sameFPURLs := range GroupByFingerprint(urls, analyses) {
			if len(sameFPURLs) < 2 {
				continue
			}
			anchor := sameFPURLs[0]
			for _, other := range sameFPURLs[1:] {
				uf.Union(anchor, other)
			}
		}
	}

	// 按主域分组
	byRegDomain := make(map[string][]string)
	for url := range activeURLs {
		analysis := analyses[url]
		if analysis.Site.RegistrableDomain == nil {
			continue
		}
		if analysis.Site.IsIP || len(analysis.NoiseReasons) > 0 || analysis.ProbeError != "" {
			continue
		}
		if analysis.LowInformation || analysis.AuthShellLike || !analysis.ComparisonReady || analysis.ShellType != "" {
			continue
		}
		byRegDomain[*analysis.Site.RegistrableDomain] = append(byRegDomain[*analysis.Site.RegistrableDomain], url)
	}

	for _, urls := range byRegDomain {
		if len(urls) < 2 {
			continue
		}
		for _, sameFPURLs := range GroupByFingerprint(urls, analyses) {
			if len(sameFPURLs) < 2 {
				continue
			}
			hosts := make(map[string]bool)
			for _, u := range sameFPURLs {
				hosts[analyses[u].Site.Host] = true
			}
			if len(hosts) < 2 {
				continue
			}
			anchor := sameFPURLs[0]
			for _, other := range sameFPURLs[1:] {
				uf.Union(anchor, other)
			}
		}
	}

	// 按 IP+端口+指纹分组
	type ipPortKey struct {
		IPs      string
		Port     int
		Status   int  // 使用 int 而非 *int，用 -1 表示 nil
		BodyHash string
		FPKey    string
	}
	byIPPortFP := make(map[ipPortKey][]string)
	for url := range activeURLs {
		analysis := analyses[url]
		if analysis.Site.IsIP || len(analysis.NoiseReasons) > 0 || analysis.ProbeError != "" {
			continue
		}
		if analysis.LowInformation || analysis.AuthShellLike || !analysis.ComparisonReady || analysis.ShellType != "" {
			continue
		}
		if len(analysis.ResolvedIPs) == 0 || analysis.BodySHA256 == "" {
			continue
		}
		statusCode := -1
		if analysis.FinalStatus != nil {
			statusCode = *analysis.FinalStatus
		}
		key := ipPortKey{
			IPs:      strings.Join(analysis.ResolvedIPs, ","),
			Port:     analysis.Site.Port,
			Status:   statusCode,
			BodyHash: analysis.BodySHA256,
			FPKey:    fingerprintKey(analysis.EquivalenceFingerprint),
		}
		byIPPortFP[key] = append(byIPPortFP[key], url)
	}

	for _, urls := range byIPPortFP {
		if len(urls) < 2 {
			continue
		}
		regDomains := make(map[string]bool)
		hosts := make(map[string]bool)
		for _, u := range urls {
			analysis := analyses[u]
			if analysis.Site.RegistrableDomain != nil {
				regDomains[*analysis.Site.RegistrableDomain] = true
			}
			hosts[analysis.Site.Host] = true
		}
		if len(regDomains) < 2 || len(hosts) < 2 {
			continue
		}
		anchor := urls[0]
		for _, other := range urls[1:] {
			uf.Union(anchor, other)
		}
	}
}

// CollectSameHostShellResults 收集同 host Shell 结果
func CollectSameHostShellResults(analyses map[string]*types.SiteAnalysis, candidateURLs map[string]bool) ([]types.MergeGroup, map[string][]string, map[string]bool) {
	var mergeGroups []types.MergeGroup
	noiseReasonMap := make(map[string][]string)
	consumedURLs := make(map[string]bool)

	type hostFPKey struct {
		Host string
		FP   string
	}
	byHostFP := make(map[hostFPKey][]string)

	for url := range candidateURLs {
		analysis := analyses[url]
		if analysis.ProbeError != "" || len(analysis.ShellMergeFingerprint) == 0 {
			continue
		}
		if analysis.ShellType != "deny_shell" && analysis.ShellType != "auth_api_shell" && analysis.ShellType != "low_information_shell" {
			continue
		}
		if analysis.Site.IsIP {
			continue
		}
		key := hostFPKey{
			Host: analysis.Site.Host,
			FP:   fingerprintKey(analysis.ShellMergeFingerprint),
		}
		byHostFP[key] = append(byHostFP[key], url)
	}

	for _, urls := range byHostFP {
		if len(urls) < 2 {
			continue
		}
		ports := make(map[int]bool)
		for _, u := range urls {
			ports[analyses[u].Site.Port] = true
		}
		if len(ports) < 2 {
			continue
		}
		sort.Strings(urls)
		for _, u := range urls {
			consumedURLs[u] = true
		}
		shellType := analyses[urls[0]].ShellType
		if shellType == "deny_shell" {
			for _, u := range urls {
				noiseReasonMap[u] = append(noiseReasonMap[u], types.NoiseReasonSameHostDeny)
			}
		} else {
			mergeGroups = append(mergeGroups, types.MergeGroup{
				GroupType:      types.GroupTypeSameHostShell,
				Representative: ChooseRepresentative(urls, analyses),
				Members:        urls,
				Reason:         types.MergeReasonSameHostShell,
			})
		}
	}

	return mergeGroups, noiseReasonMap, consumedURLs
}

// CollectSamePortSubdomainShellResults 收集同端口子域 Shell 结果
func CollectSamePortSubdomainShellResults(analyses map[string]*types.SiteAnalysis, candidateURLs map[string]bool) ([]types.MergeGroup, map[string]bool) {
	var mergeGroups []types.MergeGroup
	consumedURLs := make(map[string]bool)

	type regDomainPortIPsFPKey struct {
		RegDomain string
		Port      int
		IPs       string
		FP        string
	}
	grouped := make(map[regDomainPortIPsFPKey][]string)

	for url := range candidateURLs {
		analysis := analyses[url]
		if analysis.Site.RegistrableDomain == nil {
			continue
		}
		if analysis.ProbeError != "" || len(analysis.ShellMergeFingerprint) == 0 {
			continue
		}
		if analysis.ShellType != "deny_shell" && analysis.ShellType != "auth_api_shell" && analysis.ShellType != "low_information_shell" {
			continue
		}
		if analysis.Site.IsIP || len(analysis.ResolvedIPs) == 0 {
			continue
		}
		key := regDomainPortIPsFPKey{
			RegDomain: *analysis.Site.RegistrableDomain,
			Port:      analysis.Site.Port,
			IPs:       strings.Join(analysis.ResolvedIPs, ","),
			FP:        fingerprintKey(analysis.ShellMergeFingerprint),
		}
		grouped[key] = append(grouped[key], url)
	}

	for _, urls := range grouped {
		if len(urls) < 2 {
			continue
		}
		hosts := make(map[string]bool)
		for _, u := range urls {
			hosts[analyses[u].Site.Host] = true
		}
		if len(hosts) < 2 {
			continue
		}
		sort.Strings(urls)
		for _, u := range urls {
			consumedURLs[u] = true
		}
		mergeGroups = append(mergeGroups, types.MergeGroup{
			GroupType:      types.GroupTypeSamePortSubShell,
			Representative: ChooseRepresentative(urls, analyses),
			Members:        urls,
			Reason:         types.MergeReasonSamePortSubShell,
		})
	}

	return mergeGroups, consumedURLs
}
