package parser

import (
	"regexp"
	"strings"

	"golang.org/x/net/html"
)

// HTMLParseResult HTML 解析结果
type HTMLParseResult struct {
	Title                string
	MetaDescription      string
	MetaKeywords         string
	MetaGenerator        string
	MetaViewport         string
	Resources            []string
	NonIconResourceCount int
	FormActions          []string
	Links                []string
	BodyText             string
}

var htmlTagRe = regexp.MustCompile(`(?s)<[^>]+>`)
var whitespaceRe = regexp.MustCompile(`\s+`)

// removeScriptStyle 移除 script 和 style 标签
func removeScriptStyle(htmlStr string) string {
	var result strings.Builder
	lower := strings.ToLower(htmlStr)
	i := 0
	for i < len(htmlStr) {
		scriptIdx := strings.Index(lower[i:], "<script")
		styleIdx := strings.Index(lower[i:], "<style")

		var tagIdx int
		var tagName string
		if scriptIdx >= 0 && (styleIdx < 0 || scriptIdx < styleIdx) {
			tagIdx = scriptIdx
			tagName = "script"
		} else if styleIdx >= 0 {
			tagIdx = styleIdx
			tagName = "style"
		} else {
			result.WriteString(htmlStr[i:])
			break
		}

		result.WriteString(htmlStr[i : i+tagIdx])
		endTag := "</" + tagName + ">"
		endIdx := strings.Index(lower[i+tagIdx:], endTag)
		if endIdx >= 0 {
			i = i + tagIdx + endIdx + len(endTag)
		} else {
			i = len(htmlStr)
		}
	}
	return result.String()
}

// ParseHTML 解析 HTML 提取特征
func ParseHTML(pageURL string, body []byte) *HTMLParseResult {
	result := &HTMLParseResult{
		FormActions: make([]string, 0),
		Links:       make([]string, 0),
	}
	htmlStr := string(body)

	resources := make(map[string]struct{})
	formActions := make(map[string]struct{})
	links := make(map[string]struct{})

	tokenizer := html.NewTokenizer(strings.NewReader(htmlStr))
	inTitle := false
	var titleParts []string

	for {
		tt := tokenizer.Next()
		switch tt {
		case html.ErrorToken:
			result.Title = NormalizeText(strings.Join(titleParts, ""))
			resList := make([]string, 0, len(resources))
			for r := range resources {
				resList = append(resList, r)
			}
			result.Resources = SortStrings(resList)
			for a := range formActions {
				result.FormActions = append(result.FormActions, a)
			}
			for l := range links {
				result.Links = append(result.Links, l)
			}
			result.FormActions = SortStrings(result.FormActions)
			result.Links = SortStrings(result.Links)
			result.BodyText = StripHTMLToText(htmlStr)
			return result

		case html.StartTagToken, html.SelfClosingTagToken:
			t := tokenizer.Token()
			tagName := t.Data

			switch {
			case tagName == "title":
				inTitle = true
			case tagName == "meta":
				name := ""
				content := ""
				for _, attr := range t.Attr {
					switch strings.ToLower(attr.Key) {
					case "name":
						name = strings.ToLower(attr.Val)
					case "content":
						content = NormalizeText(attr.Val)
					}
				}
				switch name {
				case "description":
					result.MetaDescription = content
				case "keywords":
					result.MetaKeywords = content
				case "generator":
					result.MetaGenerator = content
				case "viewport":
					result.MetaViewport = content
				}
			case tagName == "script":
				src := getAttr(t, "src")
				if src != "" {
					resources["js:"+NormalizeResourceURL(pageURL, src)] = struct{}{}
					result.NonIconResourceCount++
				}
			case tagName == "link":
				rel := strings.ToLower(getAttr(t, "rel"))
				href := getAttr(t, "href")
				if href == "" {
					break
				}
				if strings.Contains(rel, "stylesheet") {
					resources["css:"+NormalizeResourceURL(pageURL, href)] = struct{}{}
					result.NonIconResourceCount++
				} else if strings.Contains(rel, "icon") {
					resources["icon:"+NormalizeResourceURL(pageURL, href)] = struct{}{}
				}
			case tagName == "form":
				action := getAttr(t, "action")
				if action != "" {
					formActions[action] = struct{}{}
				}
			case tagName == "a":
				href := getAttr(t, "href")
				if href != "" {
					links[href] = struct{}{}
				}
			}

		case html.TextToken:
			if inTitle {
				t := tokenizer.Token()
				titleParts = append(titleParts, t.Data)
			}

		case html.EndTagToken:
			t := tokenizer.Token()
			if t.Data == "title" {
				inTitle = false
			}
		}
	}
}

func getAttr(t html.Token, key string) string {
	for _, attr := range t.Attr {
		if strings.EqualFold(attr.Key, key) {
			return attr.Val
		}
	}
	return ""
}

// StripHTMLToText 去除 HTML 标签获取纯文本
func StripHTMLToText(htmlText string) string {
	text := removeScriptStyle(htmlText)
	text = htmlTagRe.ReplaceAllString(text, " ")
	return NormalizeText(text)
}

// NormalizeText 文本归一化
func NormalizeText(value string) string {
	if value == "" {
		return ""
	}
	value = html.UnescapeString(value)
	value = whitespaceRe.ReplaceAllString(value, " ")
	return strings.TrimSpace(value)
}

// NormalizeCaseFold 大小写不敏感归一化
func NormalizeCaseFold(value string) string {
	return strings.ToLower(NormalizeText(value))
}

// SortStrings 排序字符串切片
func SortStrings(s []string) []string {
	// 使用简单的排序
	for i := 0; i < len(s); i++ {
		for j := i + 1; j < len(s); j++ {
			if s[i] > s[j] {
				s[i], s[j] = s[j], s[i]
			}
		}
	}
	return s
}

// SortStringSlice 排序字符串切片（不修改原切片）
func SortStringSlice(s []string) []string {
	result := make([]string, len(s))
	copy(result, s)
	return SortStrings(result)
}

// StringSliceContains 检查字符串切片是否包含某个值
func StringSliceContains(s []string, v string) bool {
	for _, item := range s {
		if item == v {
			return true
		}
	}
	return false
}

// IsHTMLContent 判断是否为 HTML 内容
func IsHTMLContent(contentType string, body []byte, rules interface{ GetHTMLContentTypes() []string }) bool {
	ctype := strings.SplitN(contentType, ";", 2)[0]
	ctype = strings.TrimSpace(strings.ToLower(ctype))
	// 这里简化处理，直接检查常见的 HTML 类型
	if ctype == "text/html" || ctype == "application/xhtml+xml" {
		return true
	}
	sample := strings.ToLower(string(body[:min(512, len(body))]))
	sample = strings.TrimSpace(sample)
	return strings.HasPrefix(sample, "<!doctype html") || strings.HasPrefix(sample, "<html")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// FilterNonIconResources 过滤非图标资源
func FilterNonIconResources(resources []string) []string {
	var result []string
	for _, r := range resources {
		if !strings.HasPrefix(r, "icon:") {
			result = append(result, r)
		}
	}
	return result
}
