# 站点重复识别与深扫收敛工具 (Go 版本)

这是 Python 版本 `site_dedup_classifier.py` 的 Go 语言移植版本，功能完全一致。

## 构建

```bash
cd site-dedup-go
go build -o bin/sitededup ./cmd/sitededup
cp ../site_dedup_rules.yaml bin/
```

## 使用

### CLI 调用

```bash
# 基本用法
./bin/sitededup -f input.txt

# 输出 JSON 结果
./bin/sitededup -f input.txt -o result.json --details

# 自定义参数
./bin/sitededup -f input.txt -o result.json --workers 16 --timeout 5 --no-progress
```

### 参数说明

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `-f` | 输入文件，一行一个站点 | 必填 |
| `-o` | 输出 JSON 结果文件 | 可选 |
| `--rules` | 规则文件路径 | `site_dedup_rules.yaml` |
| `--timeout` | HTTP 超时时间（秒） | 3.0 |
| `--workers` | 并发数 | 8 |
| `--insecure` | 关闭 HTTPS 证书校验 | false |
| `--verify-tls` | 开启 HTTPS 证书校验 | false |
| `--retries` | 失败后重试次数 | 2 |
| `--user-agent` | 自定义 User-Agent | Chrome UA |
| `--use-env-proxy` | 启用环境变量代理 | false |
| `--details` | 输出完整 JSON 到 stdout | false |
| `--sample-limit` | 概要输出每类最多展示条数 | 5 |
| `--no-progress` | 关闭进度展示 | false |

### LIB 调用

```go
package main

import (
    "encoding/json"
    "fmt"

    "github.com/tophant/site-dedup-go/pkg/analyzer"
    "github.com/tophant/site-dedup-go/pkg/output"
    "github.com/tophant/site-dedup-go/pkg/rules"
    "github.com/tophant/site-dedup-go/pkg/parser"
    "github.com/tophant/site-dedup-go/pkg/types"
)

func main() {
    // 加载规则
    rulesConfig, _ := rules.LoadRules("site_dedup_rules.yaml")

    // 解析站点
    sites := []types.SiteInput{}
    // ... 添加站点

    // 分析站点
    analyses := make(map[string]*types.SiteAnalysis)
    for _, site := range sites {
        analyses[site.URL] = analyzer.AnalyzeSite(site, 3.0, false, rulesConfig)
    }

    // 构建输出
    result := output.BuildOutput(analyses, nil)

    // 输出 JSON
    output.WriteJSON(os.Stdout, result)
}
```

## 输出格式

输出 JSON 结构与 Python 版本完全一致，包含：

- `summary`: 统计概要
- `failure_summary`: 失败原因分类
- `noise_sites`: 噪音站点列表
- `merge_groups`: 可合并站点组
- `independent_sites`: 独立站点列表
- `details`: 各站点详细信息

## 目录结构

```
site-dedup-go/
├── cmd/sitededup/          # CLI 入口
│   └── main.go
├── internal/
│   ├── analyzer/           # 站点分析核心逻辑
│   ├── fetcher/            # HTTP 请求
│   ├── merger/             # 站点合并 (UnionFind)
│   ├── parser/             # URL/HTML 解析
│   ├── rules/              # 规则加载
│   └── output/             # 输出格式化
├── pkg/types/              # 类型定义
├── go.mod
└── go.sum
```

## 与 Python 版本的差异

1. **依赖更少**: 仅需 Go 标准库 + `gopkg.in/yaml.v3` + `golang.org/x/net/html`
2. **性能更好**: Go 原生并发，处理大量站点时速度更快
3. **部署更简单**: 编译为单个二进制文件，无需 Python 环境

## 测试

回归测试已通过，与 Python 版本输出完全一致：

- `urls.txt`: 2站点/1组可合并 ✅
- `urls403.txt`: 3站点/1组可合并 ✅
- `urls-nginx.txt`: 5站点/1组可合并 ✅
- `urls-sf.txt`: 4站点/4噪音 ✅
- `urls-zhongjian.txt`: 10站点/2组可合并 ✅
