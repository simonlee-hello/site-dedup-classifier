package types

// 分组类型
const (
	GroupTypeHTTPHTTPS          = "标准HTTP跳转HTTPS"
	GroupTypeSameHost           = "同hostname多端口等价"
	GroupTypeSameDomain         = "同主域子域等价"
	GroupTypeSameIPCrossDomain  = "同IP跨主域强等价"
	GroupTypeSameHostShell      = "同hostname多端口非业务响应页收敛"
	GroupTypeSamePortSubShell   = "同端口子域非业务响应页收敛"
)

// 独立站点原因
const (
	IndependentReasonDefault    = "默认保留为独立站点"
	IndependentReasonProbeFailed = "探测失败，无法证明可合并"
	IndependentReasonIPDirect   = "IP直连入口默认不自动合并"
	IndependentReasonLowInfo    = "页面信息量不足，不参与跨站点自动收敛"
	IndependentReasonAuthShell  = "疑似统一认证响应页，不参与跨站点自动收敛"
	IndependentReasonSignalsWeak = "五维特征不足，默认保留"
)

// 噪音原因
const (
	NoiseReasonSmallGateway = "命中小体积网关错误页"
	NoiseReasonTitle        = "命中错误页/WAF标题特征"
	NoiseReasonBody         = "命中错误页/WAF正文特征"
	NoiseReasonResponse     = "命中错误页/WAF原始响应特征"
	NoiseReasonDefaultPage  = "命中默认欢迎页"
	NoiseReasonCDNBlock     = "命中CDN/WAF拦截页"
	NoiseReasonMaintenance  = "命中明确维护页"
	NoiseReasonSameHostDeny = "同hostname多端口统一拒绝访问响应页"
)

// 合并原因
const (
	MergeReasonHTTPHTTPS          = "HTTP 入口存在明确 3xx 跳转，且落点为同 hostname 的 HTTPS 入口"
	MergeReasonSameHost           = "同一 hostname 下五个判定维度全部一致，可视为同一站点"
	MergeReasonSameHostWithRedirect = "同一 hostname 下五个判定维度全部一致，且包含标准 HTTP -> HTTPS 跳转成员"
	MergeReasonSameDomain         = "同一主域名下不同子域的五个判定维度全部一致，可视为同一站点"
	MergeReasonSameIPCrossDomain  = "不同主域名入口解析到同一 IP，且五个判定维度与正文指纹全部一致，可视为同一站点"
	MergeReasonSameHostShell      = "同一 hostname 下不同端口返回完全一致的低信息量响应页或统一认证响应页，可收敛为一个代表入口"
	MergeReasonSamePortSubShell   = "同主域不同子域在相同端口返回完全一致的低信息量响应页、统一认证响应页或统一拒绝访问响应页，且解析 IP 一致，可收敛为一个代表入口"
)

// 常量
const (
	DefaultMaxBodyBytes      = 512 * 1024
	DefaultTimeout           = 8.0
	DefaultWorkers           = 8
	DefaultSampleLimit       = 5
	RulesFileName            = "site_dedup_rules.yaml"
)

// 内容类型集合
var StructuredXMLContentTypes = map[string]bool{
	"application/xml": true,
	"text/xml":        true,
}

var StructuredJSONContentTypes = map[string]bool{
	"application/json": true,
}

// 语义 Shell 字段名集合
var SemanticShellFieldNames = map[string]bool{
	"code":            true,
	"message":         true,
	"msg":             true,
	"error":           true,
	"errors":          true,
	"success":         true,
	"resource":        true,
	"path":            true,
	"status":          true,
	"reason":          true,
	"type":            true,
	"detail":          true,
	"details":         true,
	"data":            true,
	"errorcode":       true,
	"errormessage":    true,
	"errordescription": true,
}
