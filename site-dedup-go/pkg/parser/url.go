package parser

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/simonlee-hello/site-dedup-classifier/pkg/rules"
)

// IPLiteral 检查是否为 IP 地址
func IPLiteral(host string) bool {
	// 去除 IPv6 方括号
	host = strings.Trim(host, "[]")
	return net.ParseIP(host) != nil
}

// GetRegistrableDomain 获取可注册主域名
func GetRegistrableDomain(host string, rules *rules.CompiledRules) *string {
	host = strings.ToLower(strings.Trim(host, "."))
	if host == "" || IPLiteral(host) {
		return nil
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return &host
	}
	tail2 := strings.Join(labels[len(labels)-2:], ".")
	if len(labels) >= 3 {
		tail3 := strings.Join(labels[len(labels)-3:], ".")
		if rules.MultiLevelSuffixes[tail2] {
			return &tail3
		}
	}
	return &tail2
}

// InferScheme 根据端口推测协议
func InferScheme(raw string, rules *rules.CompiledRules) string {
	raw = strings.TrimSpace(raw)
	if strings.Contains(raw, "://") {
		parsed, err := url.Parse(raw)
		if err == nil && parsed.Scheme != "" {
			return strings.ToLower(parsed.Scheme)
		}
		return "http"
	}

	// 检查 IPv6
	var port int
	var hasPort bool
	if strings.HasPrefix(raw, "[") {
		if idx := strings.Index(raw, "]"); idx >= 0 {
			after := raw[idx+1:]
			if strings.HasPrefix(after, ":") {
				p, err := strconv.Atoi(after[1:])
				if err == nil {
					port = p
					hasPort = true
				}
			}
		}
	} else if strings.Count(raw, ":") == 1 {
		parts := strings.SplitN(raw, ":", 2)
		p, err := strconv.Atoi(parts[1])
		if err == nil {
			port = p
			hasPort = true
		}
	}

	if hasPort && rules.HTTPSPortHints[port] {
		return "https"
	}
	return "http"
}

// DefaultPort 获取默认端口
func DefaultPort(scheme string) int {
	if scheme == "https" {
		return 443
	}
	return 80
}

// NormalizeSiteURL 归一化站点 URL
func NormalizeSiteURL(raw string, rules *rules.CompiledRules) (string, string, string, int, error) {
	candidate := strings.TrimSpace(raw)
	if candidate == "" {
		return "", "", "", 0, fmt.Errorf("空行")
	}
	if !strings.Contains(candidate, "://") {
		scheme := InferScheme(candidate, rules)
		candidate = scheme + "://" + candidate
	}
	parsed, err := url.Parse(candidate)
	if err != nil {
		return "", "", "", 0, fmt.Errorf("站点格式非法: %s", raw)
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", "", "", 0, fmt.Errorf("不支持的协议: %s", scheme)
	}
	host := strings.ToLower(strings.TrimSpace(parsed.Hostname()))
	if host == "" {
		return "", "", "", 0, fmt.Errorf("站点格式非法: %s", raw)
	}
	port := DefaultPort(scheme)
	if parsed.Port() != "" {
		p, err := strconv.Atoi(parsed.Port())
		if err != nil {
			return "", "", "", 0, fmt.Errorf("端口非法: %s", raw)
		}
		port = p
	}

	authority := host
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		authority = "[" + host + "]"
	}

	if port == DefaultPort(scheme) {
		return scheme + "://" + authority + "/", scheme, host, port, nil
	}
	return fmt.Sprintf("%s://%s:%d/", scheme, authority, port), scheme, host, port, nil
}

// NormalizeURLForCompare 归一化 URL 用于比较
func NormalizeURLForCompare(urlStr string) string {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return urlStr
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme == "" {
		scheme = "http"
	}
	host := strings.ToLower(parsed.Hostname())
	port := DefaultPort(scheme)
	if parsed.Port() != "" {
		p, err := strconv.Atoi(parsed.Port())
		if err == nil {
			port = p
		}
	}
	authority := host
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		authority = "[" + host + "]"
	}
	path := parsed.Path
	if path == "" {
		path = "/"
	}
	query := ""
	if parsed.RawQuery != "" {
		query = "?" + parsed.RawQuery
	}
	if port == DefaultPort(scheme) {
		return scheme + "://" + authority + path + query
	}
	return fmt.Sprintf("%s://%s:%d%s%s", scheme, authority, port, path, query)
}

// NormalizeRedirectTarget 归一化重定向目标
func NormalizeRedirectTarget(target string, fallback string) string {
	parsed, err := url.Parse(target)
	if err != nil {
		return target
	}
	// 如果是相对路径，基于 fallback 解析
	absolute := parsed.String()
	if !parsed.IsAbs() {
		base, err := url.Parse(fallback)
		if err != nil {
			return target
		}
		absolute = base.ResolveReference(parsed).String()
	}
	return NormalizeURLForCompare(absolute)
}

// NormalizeResourceURL 归一化资源 URL
func NormalizeResourceURL(pageURL string, resourceURL string) string {
	base, err := url.Parse(pageURL)
	if err != nil {
		return resourceURL
	}
	ref, err := url.Parse(resourceURL)
	if err != nil {
		return resourceURL
	}
	absolute := base.ResolveReference(ref)
	page := base

	path := absolute.Path
	if path == "" {
		path = "/"
	}
	query := ""
	if absolute.RawQuery != "" {
		query = "?" + absolute.RawQuery
	}

	// 同域名
	if strings.EqualFold(absolute.Hostname(), page.Hostname()) {
		return path + query
	}

	authority := strings.ToLower(absolute.Hostname())
	port := DefaultPort(absolute.Scheme)
	if absolute.Port() != "" {
		p, err := strconv.Atoi(absolute.Port())
		if err == nil {
			port = p
		}
	}
	if authority != "" {
		if port != DefaultPort(absolute.Scheme) {
			authority = fmt.Sprintf("%s:%d", authority, port)
		}
		return "//" + authority + path + query
	}
	return path + query
}

// CanonicalOrigin 获取规范化 Origin
func CanonicalOrigin(urlStr string) string {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return urlStr
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme == "" {
		scheme = "http"
	}
	host := strings.ToLower(parsed.Hostname())
	port := DefaultPort(scheme)
	if parsed.Port() != "" {
		p, err := strconv.Atoi(parsed.Port())
		if err == nil {
			port = p
		}
	}
	authority := host
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		authority = "[" + host + "]"
	}
	if port == DefaultPort(scheme) {
		return scheme + "://" + authority
	}
	return fmt.Sprintf("%s://%s:%d", scheme, authority, port)
}
