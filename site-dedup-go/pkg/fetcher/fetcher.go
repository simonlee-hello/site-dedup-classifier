package fetcher

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// FetchResult HTTP 请求结果
type FetchResult struct {
	FinalURL string
	StatusCode int
	Headers    map[string]string
	Body       []byte
}

// FetchOptions 请求选项
type FetchOptions struct {
	AllowRedirects bool
	Timeout        time.Duration
	Insecure       bool
	MaxBodyBytes   int
	UserAgent      string
	UseEnvProxy    bool
}

// FetchURL 发送 HTTP 请求
func FetchURL(rawURL string, opts FetchOptions) (*FetchResult, error) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: opts.Insecure,
		},
		DialContext: (&net.Dialer{
			Timeout:   opts.Timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   opts.Timeout,
		ResponseHeaderTimeout:  opts.Timeout,
		ExpectContinueTimeout:  1 * time.Second,
		DisableKeepAlives:      true,
	}

	// 处理代理
	if !opts.UseEnvProxy {
		transport.Proxy = nil
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   opts.Timeout,
	}

	if !opts.AllowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %w", err)
	}
	req.Header.Set("User-Agent", opts.UserAgent)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求失败: %w", err)
	}
	defer resp.Body.Close()

	// 限制读取大小
	bodyReader := io.LimitReader(resp.Body, int64(opts.MaxBodyBytes+1))
	body, err := io.ReadAll(bodyReader)
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %w", err)
	}
	if len(body) > opts.MaxBodyBytes {
		body = body[:opts.MaxBodyBytes]
	}

	// 收集 headers
	headers := make(map[string]string)
	for key, values := range resp.Header {
		headers[strings.ToLower(key)] = strings.Join(values, ", ")
	}

	finalURL := resp.Request.URL.String()

	return &FetchResult{
		FinalURL:   finalURL,
		StatusCode: resp.StatusCode,
		Headers:    headers,
		Body:       body,
	}, nil
}

// GetErrorMessage 获取错误信息
func GetErrorMessage(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// ClassifyProbeError 分类探测错误
func ClassifyProbeError(errorMessage string) string {
	message := strings.ToLower(errorMessage)
	if strings.Contains(message, "certificate verify failed") ||
		strings.Contains(message, "hostname mismatch") ||
		strings.Contains(message, "ssl") {
		return "SSL证书校验失败"
	}
	if strings.Contains(message, "proxyerror") ||
		strings.Contains(message, "unable to connect to proxy") ||
		strings.Contains(message, "proxy") {
		return "代理连接失败"
	}
	if strings.Contains(message, "timed out") ||
		strings.Contains(message, "read timeout") ||
		strings.Contains(message, "connect timeout") {
		return "请求超时"
	}
	if strings.Contains(message, "nodename nor servname") ||
		strings.Contains(message, "name or service not known") ||
		strings.Contains(message, "temporary failure in name resolution") {
		return "DNS解析失败"
	}
	if strings.Contains(message, "connection refused") {
		return "连接被拒绝"
	}
	if strings.Contains(message, "remote end closed connection without response") {
		return "远端直接关闭连接"
	}
	if strings.Contains(message, "connection reset") ||
		strings.Contains(message, "connection aborted") {
		return "连接被重置或中断"
	}
	return "其他请求失败"
}

// ShouldRetryException 判断是否应该重试
func ShouldRetryException(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	nonRetryKeywords := []string{
		"certificate verify failed",
		"hostname mismatch",
		"self-signed certificate",
		"unable to get local issuer certificate",
		"wrong version number",
		"tlsv1 alert",
		"sslv3 alert",
	}
	for _, keyword := range nonRetryKeywords {
		if strings.Contains(message, keyword) {
			return false
		}
	}
	return true
}

// GetBaseContentType 获取基础 Content-Type
func GetBaseContentType(contentType string) string {
	parts := strings.SplitN(contentType, ";", 2)
	return strings.TrimSpace(strings.ToLower(parts[0]))
}

// ParseURL 解析 URL
func ParseURL(rawURL string) (*url.URL, error) {
	return url.Parse(rawURL)
}
