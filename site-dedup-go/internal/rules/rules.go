package rules

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// CompiledRules 编译后的规则
type CompiledRules struct {
	MaxBodyBytes               int
	DefaultTimeout             float64
	UserAgent                  string
	RetryAttempts              int
	RetryBackoffSeconds        float64
	VerifyTLS                  bool
	UseEnvProxy                bool
	KeyPaths                   []string
	HTTPSPortHints             map[int]bool
	MultiLevelSuffixes         map[string]bool
	HTMLContentTypes           []string
	SmallGatewayStatuses       map[int]bool
	SmallGatewayBodyLength     int
	LowInfoBodyLength          int
	LowInfoMinNonIconResources int
	MaintenanceTitlePatterns   []*regexp.Regexp
	MaintenanceBodyPatterns    []*regexp.Regexp
	DenyStatuses               map[int]bool
	DenyTextPatterns           []*regexp.Regexp
	AuthContentTypes           map[string]bool
	AuthTextPatterns           []*regexp.Regexp
	CDNServers                 map[string]bool
	CDNStatuses                map[int]bool
	CDNKeywords                []string
	NoiseTitlePatterns         []*regexp.Regexp
	NoiseBodyPatterns          []*regexp.Regexp
	NoiseResponsePatterns      []*regexp.Regexp
	DefaultPagePatterns        []*regexp.Regexp
	AuthShellPatterns          []*regexp.Regexp
	BusinessTextPattern        *regexp.Regexp
}

// yamlConfig YAML 配置结构
type yamlConfig struct {
	DefaultTimeout      float64                   `yaml:"default_timeout"`
	MaxBodyBytes        int                       `yaml:"max_body_bytes"`
	Network             networkConfig             `yaml:"network"`
	HTTP                httpConfig                `yaml:"http"`
	RegistrableDomain   registrableDomainConfig   `yaml:"registrable_domain"`
	Noise               noiseConfig               `yaml:"noise"`
	LowInformation      lowInformationConfig      `yaml:"low_information"`
	ResponseShells      responseShellsConfig      `yaml:"response_shells"`
	AuthShellPatterns   []string                  `yaml:"auth_shell_patterns"`
	BusinessTextPattern string                    `yaml:"business_text_pattern"`
}

type networkConfig struct {
	UserAgent           string  `yaml:"user_agent"`
	RetryAttempts       int     `yaml:"retry_attempts"`
	RetryBackoffSeconds float64 `yaml:"retry_backoff_seconds"`
	VerifyTLS           bool    `yaml:"verify_tls"`
	UseEnvProxy         bool    `yaml:"use_env_proxy"`
}

type httpConfig struct {
	HTTPSPortHints   []int    `yaml:"https_port_hints"`
	HTMLContentTypes []string `yaml:"html_content_types"`
	KeyPaths         []string `yaml:"key_paths"`
}

type registrableDomainConfig struct {
	MultiLevelSuffixes []string `yaml:"multi_level_suffixes"`
}

type noiseConfig struct {
	SmallGatewayStatuses   []int    `yaml:"small_gateway_statuses"`
	SmallGatewayBodyLength int     `yaml:"small_gateway_body_length"`
	CDNServers             []string `yaml:"cdn_servers"`
	CDNStatuses            []int    `yaml:"cdn_statuses"`
	CDNBodyKeywords        []string `yaml:"cdn_body_keywords"`
	TitlePatterns          []string `yaml:"title_patterns"`
	BodyPatterns           []string `yaml:"body_patterns"`
	ResponsePatterns       []string `yaml:"response_patterns"`
	DefaultPagePatterns    []string `yaml:"default_page_patterns"`
}

type lowInformationConfig struct {
	BodyLengthThreshold  int `yaml:"body_length_threshold"`
	MinNonIconResources  int `yaml:"min_non_icon_resources"`
}

type responseShellsConfig struct {
	MaintenanceTitlePatterns []string `yaml:"maintenance_title_patterns"`
	MaintenanceBodyPatterns  []string `yaml:"maintenance_body_patterns"`
	DenyStatuses             []int    `yaml:"deny_statuses"`
	DenyTextPatterns         []string `yaml:"deny_text_patterns"`
	AuthContentTypes         []string `yaml:"auth_content_types"`
	AuthTextPatterns         []string `yaml:"auth_text_patterns"`
}

func compilePatterns(patterns []string) []*regexp.Regexp {
	result := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		// 转换 Python Unicode 转义
		p = convertPythonUnicodeEscape(p)
		re, err := regexp.Compile("(?i)" + p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "警告: 编译正则失败: %s: %v\n", p, err)
			continue
		}
		result = append(result, re)
	}
	return result
}

// convertPythonUnicodeEscape 将 Python 风格的 \uXXXX 转换为 Go 的 \x{XXXX}
func convertPythonUnicodeEscape(pattern string) string {
	var result strings.Builder
	i := 0
	for i < len(pattern) {
		if i+5 < len(pattern) && pattern[i] == '\\' && pattern[i+1] == 'u' {
			// 找到 \uXXXX
			hex := pattern[i+2 : i+6]
			result.WriteString(`\x{`)
			result.WriteString(hex)
			result.WriteString(`}`)
			i += 6
		} else {
			result.WriteByte(pattern[i])
			i++
		}
	}
	return result.String()
}

func intSliceToSet(items []int) map[int]bool {
	set := make(map[int]bool, len(items))
	for _, v := range items {
		set[v] = true
	}
	return set
}

func stringSliceToCaseFoldSet(items []string) map[string]bool {
	set := make(map[string]bool, len(items))
	for _, v := range items {
		set[strings.ToLower(v)] = true
	}
	return set
}

// LoadRules 从文件加载规则
func LoadRules(path string) (*CompiledRules, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取规则文件失败: %w", err)
	}

	var config yamlConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("解析规则文件失败: %w", err)
	}

	// 设置默认值
	maxBodyBytes := config.MaxBodyBytes
	if maxBodyBytes <= 0 {
		maxBodyBytes = 512 * 1024
	}

	defaultTimeout := config.DefaultTimeout
	if defaultTimeout <= 0 {
		defaultTimeout = 8.0
	}

	userAgent := config.Network.UserAgent
	if userAgent == "" {
		userAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36"
	}

	retryAttempts := config.Network.RetryAttempts
	if retryAttempts < 0 {
		retryAttempts = 0
	}

	retryBackoff := config.Network.RetryBackoffSeconds
	if retryBackoff < 0 {
		retryBackoff = 0
	}

	keyPaths := config.HTTP.KeyPaths
	if len(keyPaths) == 0 {
		keyPaths = []string{"/robots.txt", "/favicon.ico", "/sitemap.xml", "/.well-known/"}
	}

	httpsPortHints := config.HTTP.HTTPSPortHints
	if len(httpsPortHints) == 0 {
		httpsPortHints = []int{443, 8443, 9443, 10443}
	}

	htmlContentTypes := config.HTTP.HTMLContentTypes
	if len(htmlContentTypes) == 0 {
		htmlContentTypes = []string{"text/html", "application/xhtml+xml"}
	}

	smallGatewayStatuses := config.Noise.SmallGatewayStatuses
	if len(smallGatewayStatuses) == 0 {
		smallGatewayStatuses = []int{502, 503, 504}
	}

	smallGatewayBodyLength := config.Noise.SmallGatewayBodyLength
	if smallGatewayBodyLength <= 0 {
		smallGatewayBodyLength = 2048
	}

	lowInfoBodyLength := config.LowInformation.BodyLengthThreshold
	if lowInfoBodyLength <= 0 {
		lowInfoBodyLength = 512
	}

	lowInfoMinNonIcon := config.LowInformation.MinNonIconResources
	if lowInfoMinNonIcon <= 0 {
		lowInfoMinNonIcon = 2
	}

	denyStatuses := config.ResponseShells.DenyStatuses
	if len(denyStatuses) == 0 {
		denyStatuses = []int{401, 403}
	}

	authContentTypes := config.ResponseShells.AuthContentTypes
	if len(authContentTypes) == 0 {
		authContentTypes = []string{"application/json"}
	}

	cdnServers := config.Noise.CDNServers
	if len(cdnServers) == 0 {
		cdnServers = []string{"cloudflare", "cloudfront", "akamai"}
	}

	cdnStatuses := config.Noise.CDNStatuses
	if len(cdnStatuses) == 0 {
		cdnStatuses = []int{403, 503}
	}

	cdnKeywords := config.Noise.CDNBodyKeywords
	if len(cdnKeywords) == 0 {
		cdnKeywords = []string{"access denied", "attention required", "cloudflare ray id"}
	}

	businessTextPattern := config.BusinessTextPattern
	if businessTextPattern == "" {
		businessTextPattern = `[A-Za-z0-9\x{4e00}-\x{9fff}]{4,}`
	}
	// 处理 Python 风格的 Unicode 转义 (\uXXXX -> \x{XXXX})
	businessTextPattern = convertPythonUnicodeEscape(businessTextPattern)
	bizRe, err := regexp.Compile(businessTextPattern)
	if err != nil {
		return nil, fmt.Errorf("编译业务文本正则失败: %w", err)
	}

	rules := &CompiledRules{
		MaxBodyBytes:               maxBodyBytes,
		DefaultTimeout:             defaultTimeout,
		UserAgent:                  userAgent,
		RetryAttempts:              retryAttempts,
		RetryBackoffSeconds:        retryBackoff,
		VerifyTLS:                  config.Network.VerifyTLS,
		UseEnvProxy:                config.Network.UseEnvProxy,
		KeyPaths:                   keyPaths,
		HTTPSPortHints:             intSliceToSet(httpsPortHints),
		MultiLevelSuffixes:         stringSliceToCaseFoldSet(config.RegistrableDomain.MultiLevelSuffixes),
		HTMLContentTypes:           htmlContentTypes,
		SmallGatewayStatuses:       intSliceToSet(smallGatewayStatuses),
		SmallGatewayBodyLength:     smallGatewayBodyLength,
		LowInfoBodyLength:          lowInfoBodyLength,
		LowInfoMinNonIconResources: lowInfoMinNonIcon,
		MaintenanceTitlePatterns:   compilePatterns(config.ResponseShells.MaintenanceTitlePatterns),
		MaintenanceBodyPatterns:    compilePatterns(config.ResponseShells.MaintenanceBodyPatterns),
		DenyStatuses:               intSliceToSet(denyStatuses),
		DenyTextPatterns:           compilePatterns(config.ResponseShells.DenyTextPatterns),
		AuthContentTypes:           stringSliceToCaseFoldSet(authContentTypes),
		AuthTextPatterns:           compilePatterns(config.ResponseShells.AuthTextPatterns),
		CDNServers:                 stringSliceToCaseFoldSet(cdnServers),
		CDNStatuses:                intSliceToSet(cdnStatuses),
		CDNKeywords:                cdnKeywords,
		NoiseTitlePatterns:         compilePatterns(config.Noise.TitlePatterns),
		NoiseBodyPatterns:          compilePatterns(config.Noise.BodyPatterns),
		NoiseResponsePatterns:      compilePatterns(config.Noise.ResponsePatterns),
		DefaultPagePatterns:        compilePatterns(config.Noise.DefaultPagePatterns),
		AuthShellPatterns:          compilePatterns(config.AuthShellPatterns),
		BusinessTextPattern:        bizRe,
	}

	return rules, nil
}
