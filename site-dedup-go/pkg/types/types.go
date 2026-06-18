package types

// PathProbe 路径探测结果
type PathProbe struct {
	Path           string        `json:"path"`
	StatusCode     *int          `json:"status_code"`
	BodySHA256     string        `json:"body_sha256"`
	ContentType    string        `json:"content_type"`
	ETag           string        `json:"etag"`
	LastModified   string        `json:"last_modified"`
	MergeSignature []interface{} `json:"-"`
	Error          string        `json:"error,omitempty"`
}

// SiteInput 输入站点信息
type SiteInput struct {
	Raw               string  `json:"raw"`
	URL               string  `json:"url"`
	Scheme            string  `json:"scheme"`
	Host              string  `json:"host"`
	Port              int     `json:"port"`
	IsIP              bool    `json:"is_ip"`
	RegistrableDomain *string `json:"registrable_domain"`
}

// SiteAnalysis 站点分析结果
type SiteAnalysis struct {
	Site                  SiteInput               `json:"site"`
	ProbeError            string                  `json:"probe_error,omitempty"`
	OriginalStatus        *int                    `json:"original_status,omitempty"`
	FinalStatus           *int                    `json:"final_status,omitempty"`
	RedirectTarget        string                  `json:"redirect_target,omitempty"`
	FinalURL              string                  `json:"final_url,omitempty"`
	FinalURLNormalized    string                  `json:"final_url_normalized,omitempty"`
	FinalOrigin           string                  `json:"final_origin,omitempty"`
	Title                 string                  `json:"title,omitempty"`
	MetaDescription       string                  `json:"meta_description,omitempty"`
	MetaKeywords          string                  `json:"meta_keywords,omitempty"`
	MetaGenerator         string                  `json:"meta_generator,omitempty"`
	MetaViewport          string                  `json:"meta_viewport,omitempty"`
	BodyLength            int                     `json:"body_length,omitempty"`
	BodySHA256            string                  `json:"body_sha256,omitempty"`
	BodyTextExcerpt       string                  `json:"body_text_excerpt,omitempty"`
	ResponseTextExcerpt   string                  `json:"response_text_excerpt,omitempty"`
	ETag                  string                  `json:"etag,omitempty"`
	LastModified          string                  `json:"last_modified,omitempty"`
	Server                string                  `json:"server,omitempty"`
	XPoweredBy            string                  `json:"x_powered_by,omitempty"`
	ContentType           string                  `json:"content_type,omitempty"`
	Resources             []string                `json:"resources,omitempty"`
	NonIconResourceCount  int                     `json:"non_icon_resource_count,omitempty"`
	KeyPaths              []PathProbe             `json:"key_paths,omitempty"`
	NoiseReasons          []string                `json:"noise_reasons,omitempty"`
	DefaultPageHit        bool                    `json:"default_page_hit,omitempty"`
	LowInformation        bool                    `json:"low_information,omitempty"`
	AuthShellLike         bool                    `json:"auth_shell_like,omitempty"`
	ShellType             string                  `json:"shell_type,omitempty"`
	ShellReason           string                  `json:"shell_reason,omitempty"`
	ComparisonReady       bool                    `json:"comparison_ready,omitempty"`
	ResolvedIPs           []string                `json:"resolved_ips,omitempty"`
	HeaderSignature       []interface{}           `json:"-"`
	RedirectSignature     []interface{}           `json:"-"`
	StructureSignature    []interface{}           `json:"-"`
	ResourceSignature     []interface{}           `json:"-"`
	KeyPathSignature      []interface{}           `json:"-"`
	EquivalenceFingerprint []interface{}          `json:"-"`
	ShellExactFingerprint []interface{}           `json:"-"`
	ShellMergeFingerprint []interface{}           `json:"-"`
}

// MergeGroup 可合并站点组
type MergeGroup struct {
	GroupType      string   `json:"group_type"`
	Representative string   `json:"representative"`
	Members        []string `json:"members"`
	Reason         string   `json:"reason"`
}

// OutputResult 最终输出结果
type OutputResult struct {
	Summary           map[string]interface{} `json:"summary"`
	FailureSummary    []FailureSummaryItem   `json:"failure_summary"`
	NoiseSites        []NoiseSiteItem        `json:"noise_sites"`
	MergeGroups       []MergeGroupItem       `json:"merge_groups"`
	IndependentSites  []IndependentSiteItem  `json:"independent_sites"`
	Details           map[string]interface{} `json:"details"`
}

// FailureSummaryItem 失败原因概要
type FailureSummaryItem struct {
	Category   string   `json:"category"`
	Count      int      `json:"count"`
	SampleURLs []string `json:"sample_urls"`
}

// NoiseSiteItem 噪音站点
type NoiseSiteItem struct {
	URL        string   `json:"url"`
	Reasons    []string `json:"reasons"`
	Title      string   `json:"title"`
	StatusCode *int     `json:"status_code"`
}

// MergeGroupItem 可合并站点组输出
type MergeGroupItem struct {
	GroupType      string   `json:"group_type"`
	Representative string   `json:"representative"`
	MemberCount    int      `json:"member_count"`
	Members        []string `json:"members"`
	Reason         string   `json:"reason"`
}

// IndependentSiteItem 独立站点
type IndependentSiteItem struct {
	URL        string `json:"url"`
	Reason     string `json:"reason"`
	Title      string `json:"title"`
	StatusCode *int   `json:"status_code"`
}
