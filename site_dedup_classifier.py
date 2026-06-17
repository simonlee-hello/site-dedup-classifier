#!/usr/bin/env python3
"""
按“站点重复识别与深扫收敛分析及方案——安全视角”对站点批量分类：
- 噪音站点
- 可合并站点组
- 独立站点
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import html
import ipaddress
import json
import re
import socket
import ssl
import sys
import time
import warnings
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib import error as urllib_error
from urllib import parse as urllib_parse
from urllib import request as urllib_request
from xml.etree import ElementTree as ET

try:
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", module="urllib3")
        import requests  # type: ignore
except ImportError:  # pragma: no cover - optional dependency
    requests = None

try:
    import yaml  # type: ignore
except ImportError:  # pragma: no cover - optional dependency
    yaml = None

try:
    from rich import box
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
except ImportError:  # pragma: no cover - optional dependency
    box = None
    Console = None
    Panel = None
    Table = None


RULES_FILE_NAME = "site_dedup_rules.yaml"
DEFAULT_MAX_BODY_BYTES = 512 * 1024
DEFAULT_TIMEOUT = 8.0
DEFAULT_WORKERS = 8
DEFAULT_SAMPLE_LIMIT = 5

GROUP_TYPE_HTTP_HTTPS = "标准HTTP跳转HTTPS"
GROUP_TYPE_SAME_HOST = "同hostname多端口等价"
GROUP_TYPE_SAME_DOMAIN = "同主域子域等价"
GROUP_TYPE_SAME_IP_CROSS_DOMAIN = "同IP跨主域强等价"
GROUP_TYPE_SAME_HOST_SHELL = "同hostname多端口非业务响应页收敛"
GROUP_TYPE_SAME_PORT_SUBDOMAIN_SHELL = "同端口子域非业务响应页收敛"

INDEPENDENT_REASON_DEFAULT = "默认保留为独立站点"
INDEPENDENT_REASON_PROBE_FAILED = "探测失败，无法证明可合并"
INDEPENDENT_REASON_IP_DIRECT = "IP直连入口默认不自动合并"
INDEPENDENT_REASON_LOW_INFO = "页面信息量不足，不参与跨站点自动收敛"
INDEPENDENT_REASON_AUTH_SHELL = "疑似统一认证响应页，不参与跨站点自动收敛"
INDEPENDENT_REASON_SIGNALS_WEAK = "五维特征不足，默认保留"

NOISE_REASON_SMALL_GATEWAY = "命中小体积网关错误页"
NOISE_REASON_TITLE = "命中错误页/WAF标题特征"
NOISE_REASON_BODY = "命中错误页/WAF正文特征"
NOISE_REASON_RESPONSE = "命中错误页/WAF原始响应特征"
NOISE_REASON_DEFAULT_PAGE = "命中默认欢迎页"
NOISE_REASON_CDN_BLOCK = "命中CDN/WAF拦截页"
NOISE_REASON_MAINTENANCE = "命中明确维护页"
NOISE_REASON_SAME_HOST_DENY = "同hostname多端口统一拒绝访问响应页"

MERGE_REASON_HTTP_HTTPS = "HTTP 入口存在明确 3xx 跳转，且落点为同 hostname 的 HTTPS 入口"
MERGE_REASON_SAME_HOST = "同一 hostname 下五个判定维度全部一致，可视为同一站点"
MERGE_REASON_SAME_HOST_WITH_REDIRECT = "同一 hostname 下五个判定维度全部一致，且包含标准 HTTP -> HTTPS 跳转成员"
MERGE_REASON_SAME_DOMAIN = "同一主域名下不同子域的五个判定维度全部一致，可视为同一站点"
MERGE_REASON_SAME_IP_CROSS_DOMAIN = "不同主域名入口解析到同一 IP，且五个判定维度与正文指纹全部一致，可视为同一站点"
MERGE_REASON_SAME_HOST_SHELL = "同一 hostname 下不同端口返回完全一致的低信息量响应页或统一认证响应页，可收敛为一个代表入口"
MERGE_REASON_SAME_PORT_SUBDOMAIN_SHELL = "同主域不同子域在相同端口返回完全一致的低信息量响应页、统一认证响应页或统一拒绝访问响应页，且解析 IP 一致，可收敛为一个代表入口"

STRUCTURED_XML_CONTENT_TYPES = {"application/xml", "text/xml"}
STRUCTURED_JSON_CONTENT_TYPES = {"application/json"}
SEMANTIC_SHELL_FIELD_NAMES = {
    "code",
    "message",
    "msg",
    "error",
    "errors",
    "success",
    "resource",
    "path",
    "status",
    "reason",
    "type",
    "detail",
    "details",
    "data",
    "errorcode",
    "errormessage",
    "errordescription",
}

RICH_AVAILABLE = all(item is not None for item in (box, Console, Panel, Table))


@dataclass
class CompiledRules:
    max_body_bytes: int
    default_timeout: float
    user_agent: str
    retry_attempts: int
    retry_backoff_seconds: float
    verify_tls: bool
    use_env_proxy: bool
    key_paths: Tuple[str, ...]
    https_port_hints: Set[int]
    multi_level_suffixes: Set[str]
    html_content_types: Tuple[str, ...]
    small_gateway_statuses: Set[int]
    small_gateway_body_length: int
    low_info_body_length: int
    low_info_min_non_icon_resources: int
    maintenance_title_patterns: Tuple[re.Pattern[str], ...]
    maintenance_body_patterns: Tuple[re.Pattern[str], ...]
    deny_statuses: Set[int]
    deny_text_patterns: Tuple[re.Pattern[str], ...]
    auth_content_types: Set[str]
    auth_text_patterns: Tuple[re.Pattern[str], ...]
    cdn_servers: Set[str]
    cdn_statuses: Set[int]
    cdn_keywords: Tuple[str, ...]
    noise_title_patterns: Tuple[re.Pattern[str], ...]
    noise_body_patterns: Tuple[re.Pattern[str], ...]
    noise_response_patterns: Tuple[re.Pattern[str], ...]
    default_page_patterns: Tuple[re.Pattern[str], ...]
    auth_shell_patterns: Tuple[re.Pattern[str], ...]
    business_text_pattern: re.Pattern[str]


@dataclass
class PathProbe:
    path: str
    status_code: Optional[int]
    body_sha256: str
    content_type: str
    etag: str
    last_modified: str
    merge_signature: Tuple[object, ...] = ()
    error: str = ""


@dataclass
class SiteInput:
    raw: str
    url: str
    scheme: str
    host: str
    port: int
    is_ip: bool
    registrable_domain: Optional[str]


@dataclass
class SiteAnalysis:
    site: SiteInput
    probe_error: str = ""
    original_status: Optional[int] = None
    final_status: Optional[int] = None
    redirect_target: str = ""
    final_url: str = ""
    final_url_normalized: str = ""
    final_origin: str = ""
    title: str = ""
    meta_description: str = ""
    meta_keywords: str = ""
    meta_generator: str = ""
    meta_viewport: str = ""
    body_length: int = 0
    body_sha256: str = ""
    body_text_excerpt: str = ""
    response_text_excerpt: str = ""
    etag: str = ""
    last_modified: str = ""
    server: str = ""
    x_powered_by: str = ""
    content_type: str = ""
    resources: Tuple[str, ...] = ()
    non_icon_resource_count: int = 0
    key_paths: Tuple[PathProbe, ...] = ()
    noise_reasons: Tuple[str, ...] = ()
    default_page_hit: bool = False
    low_information: bool = False
    auth_shell_like: bool = False
    shell_type: str = ""
    shell_reason: str = ""
    comparison_ready: bool = False
    resolved_ips: Tuple[str, ...] = ()
    header_signature: Tuple[str, ...] = ()
    redirect_signature: Tuple[str, ...] = ()
    structure_signature: Tuple[str, ...] = ()
    resource_signature: Tuple[str, ...] = ()
    key_path_signature: Tuple[Tuple[str, Optional[int], str, str, str, str], ...] = ()
    equivalence_fingerprint: Tuple[object, ...] = ()
    shell_exact_fingerprint: Tuple[object, ...] = ()
    shell_merge_fingerprint: Tuple[object, ...] = ()


@dataclass
class MergeGroup:
    group_type: str
    representative: str
    members: List[str]
    reason: str


class PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.in_title = False
        self.title_parts: List[str] = []
        self.meta: Dict[str, str] = {}
        self.resources: Set[str] = set()
        self.non_icon_resource_count = 0
        self.form_actions: Set[str] = set()
        self.links: Set[str] = set()

    def handle_starttag(self, tag: str, attrs: Sequence[Tuple[str, Optional[str]]]) -> None:
        mapping = {key.lower(): (value or "") for key, value in attrs}
        tag = tag.lower()
        if tag == "title":
            self.in_title = True
            return
        if tag == "meta":
            name = mapping.get("name", "").lower()
            if name in {"description", "keywords", "generator", "viewport"}:
                self.meta[name] = normalize_text(mapping.get("content", ""))
            return
        if tag == "script" and mapping.get("src"):
            self.resources.add(f"js:{mapping['src']}")
            self.non_icon_resource_count += 1
            return
        if tag == "link":
            rel = mapping.get("rel", "").lower()
            href = mapping.get("href", "")
            if not href:
                return
            if "stylesheet" in rel:
                self.resources.add(f"css:{href}")
                self.non_icon_resource_count += 1
                return
            if "icon" in rel:
                self.resources.add(f"icon:{href}")
                return
        if tag == "form" and mapping.get("action"):
            self.form_actions.add(mapping["action"])
            return
        if tag == "a" and mapping.get("href"):
            self.links.add(mapping["href"])

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self.in_title = False

    def handle_data(self, data: str) -> None:
        if self.in_title:
            self.title_parts.append(data)


class NoRedirectHandler(urllib_request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None


class UnionFind:
    def __init__(self, items: Iterable[str]) -> None:
        self.parent = {item: item for item in items}

    def find(self, item: str) -> str:
        parent = self.parent[item]
        if parent != item:
            self.parent[item] = self.find(parent)
        return self.parent[item]

    def union(self, left: str, right: str) -> None:
        left_root = self.find(left)
        right_root = self.find(right)
        if left_root != right_root:
            self.parent[right_root] = left_root

    def groups(self) -> Dict[str, List[str]]:
        grouped: Dict[str, List[str]] = {}
        for item in self.parent:
            root = self.find(item)
            grouped.setdefault(root, []).append(item)
        return grouped


def parse_yaml_scalar(text: str) -> Any:
    value = text.strip()
    if value == "":
        return ""
    if (value.startswith("'") and value.endswith("'")) or (value.startswith('"') and value.endswith('"')):
        return value[1:-1]
    lower_value = value.lower()
    if lower_value == "true":
        return True
    if lower_value == "false":
        return False
    if lower_value in {"null", "none"}:
        return None
    if re.fullmatch(r"-?\d+", value):
        return int(value)
    if re.fullmatch(r"-?\d+\.\d+", value):
        return float(value)
    return value


def next_significant_line(lines: Sequence[Tuple[int, str]], start: int) -> Optional[Tuple[int, str, int]]:
    index = start
    while index < len(lines):
        indent, content = lines[index]
        if content:
            return indent, content, index
        index += 1
    return None


def parse_yaml_block(lines: Sequence[Tuple[int, str]], start: int, indent: int) -> Tuple[Any, int]:
    current = next_significant_line(lines, start)
    if current is None:
        return {}, start
    first_indent, first_content, first_index = current
    if first_indent < indent:
        return {}, first_index
    if first_indent > indent:
        indent = first_indent

    if first_content.startswith("- "):
        items: List[Any] = []
        index = first_index
        while index < len(lines):
            current = next_significant_line(lines, index)
            if current is None:
                break
            line_indent, content, current_index = current
            if line_indent < indent:
                break
            if line_indent > indent:
                raise ValueError(f"YAML 缩进非法，行 {current_index + 1}")
            if not content.startswith("- "):
                break
            item_text = content[2:].strip()
            index = current_index + 1
            if item_text:
                items.append(parse_yaml_scalar(item_text))
                continue
            child = next_significant_line(lines, index)
            if child is None or child[0] <= line_indent:
                items.append(None)
                continue
            nested, index = parse_yaml_block(lines, index, child[0])
            items.append(nested)
        return items, index

    mapping: Dict[str, Any] = {}
    index = first_index
    while index < len(lines):
        current = next_significant_line(lines, index)
        if current is None:
            break
        line_indent, content, current_index = current
        if line_indent < indent:
            break
        if line_indent > indent:
            raise ValueError(f"YAML 缩进非法，行 {current_index + 1}")
        if content.startswith("- "):
            break
        if ":" not in content:
            raise ValueError(f"YAML 键值格式非法，行 {current_index + 1}: {content}")
        key, rest = content.split(":", 1)
        key = key.strip()
        rest = rest.strip()
        index = current_index + 1
        if rest:
            mapping[key] = parse_yaml_scalar(rest)
            continue
        child = next_significant_line(lines, index)
        if child is None or child[0] <= line_indent:
            mapping[key] = {}
            continue
        nested, index = parse_yaml_block(lines, index, child[0])
        mapping[key] = nested
    return mapping, index


def load_yaml_subset(path: Path) -> Dict[str, Any]:
    lines: List[Tuple[int, str]] = []
    with path.open("r", encoding="utf-8") as handle:
        for raw_line in handle:
            stripped_newline = raw_line.rstrip("\n\r")
            stripped = stripped_newline.strip()
            if not stripped or stripped.startswith("#"):
                lines.append((0, ""))
                continue
            indent = len(stripped_newline) - len(stripped_newline.lstrip(" "))
            lines.append((indent, stripped_newline[indent:]))
    parsed, _ = parse_yaml_block(lines, 0, 0)
    if not isinstance(parsed, dict):
        raise ValueError(f"规则文件顶层必须是对象: {path}")
    return parsed


def load_structured_file(path: Path) -> Dict[str, Any]:
    if yaml is not None:
        with path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
        if not isinstance(data, dict):
            raise ValueError(f"规则文件顶层必须是对象: {path}")
        return data
    return load_yaml_subset(path)


def compile_patterns(patterns: Sequence[str]) -> Tuple[re.Pattern[str], ...]:
    return tuple(re.compile(pattern, re.I) for pattern in patterns)


def load_rules(path: Path) -> CompiledRules:
    raw = load_structured_file(path)

    http_rules = raw.get("http", {})
    network_rules = raw.get("network", {})
    noise_rules = raw.get("noise", {})
    low_info_rules = raw.get("low_information", {})
    shell_rules = raw.get("response_shells", {})
    registrable_domain_rules = raw.get("registrable_domain", {})

    business_text_pattern = raw.get("business_text_pattern", r"[A-Za-z0-9\u4e00-\u9fff]{4,}")
    return CompiledRules(
        max_body_bytes=int(raw.get("max_body_bytes", DEFAULT_MAX_BODY_BYTES)),
        default_timeout=float(raw.get("default_timeout", DEFAULT_TIMEOUT)),
        user_agent=str(network_rules.get("user_agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36")),
        retry_attempts=max(0, int(network_rules.get("retry_attempts", 2))),
        retry_backoff_seconds=max(0.0, float(network_rules.get("retry_backoff_seconds", 0.6))),
        verify_tls=bool(network_rules.get("verify_tls", False)),
        use_env_proxy=bool(network_rules.get("use_env_proxy", False)),
        key_paths=tuple(http_rules.get("key_paths", ["/robots.txt", "/favicon.ico", "/sitemap.xml", "/.well-known/"])),
        https_port_hints={int(item) for item in http_rules.get("https_port_hints", [443, 8443, 9443, 10443])},
        multi_level_suffixes={str(item).lower() for item in registrable_domain_rules.get("multi_level_suffixes", [])},
        html_content_types=tuple(http_rules.get("html_content_types", ["text/html", "application/xhtml+xml"])),
        small_gateway_statuses={int(item) for item in noise_rules.get("small_gateway_statuses", [502, 503, 504])},
        small_gateway_body_length=int(noise_rules.get("small_gateway_body_length", 2048)),
        low_info_body_length=int(low_info_rules.get("body_length_threshold", 512)),
        low_info_min_non_icon_resources=int(low_info_rules.get("min_non_icon_resources", 2)),
        maintenance_title_patterns=compile_patterns(shell_rules.get("maintenance_title_patterns", [])),
        maintenance_body_patterns=compile_patterns(shell_rules.get("maintenance_body_patterns", [])),
        deny_statuses={int(item) for item in shell_rules.get("deny_statuses", [401, 403])},
        deny_text_patterns=compile_patterns(shell_rules.get("deny_text_patterns", [])),
        auth_content_types={str(item).strip().lower() for item in shell_rules.get("auth_content_types", ["application/json"])},
        auth_text_patterns=compile_patterns(shell_rules.get("auth_text_patterns", [])),
        cdn_servers={str(item).casefold() for item in noise_rules.get("cdn_servers", ["cloudflare", "cloudfront", "akamai"])},
        cdn_statuses={int(item) for item in noise_rules.get("cdn_statuses", [403, 503])},
        cdn_keywords=tuple(str(item).casefold() for item in noise_rules.get("cdn_body_keywords", ["access denied", "attention required", "cloudflare ray id"])),
        noise_title_patterns=compile_patterns(noise_rules.get("title_patterns", [])),
        noise_body_patterns=compile_patterns(noise_rules.get("body_patterns", [])),
        noise_response_patterns=compile_patterns(noise_rules.get("response_patterns", [])),
        default_page_patterns=compile_patterns(noise_rules.get("default_page_patterns", [])),
        auth_shell_patterns=compile_patterns(raw.get("auth_shell_patterns", [])),
        business_text_pattern=re.compile(business_text_pattern),
    )


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def normalize_text(value: Optional[str]) -> str:
    if not value:
        return ""
    value = html.unescape(value)
    value = re.sub(r"\s+", " ", value).strip()
    return value


def normalize_casefold(value: Optional[str]) -> str:
    return normalize_text(value).casefold()


def is_ip_literal(host: str) -> bool:
    raw = host.strip("[]")
    try:
        ipaddress.ip_address(raw)
        return True
    except ValueError:
        return False


def get_registrable_domain(host: str, rules: CompiledRules) -> Optional[str]:
    host = host.lower().strip(".")
    if not host or is_ip_literal(host):
        return None
    labels = host.split(".")
    if len(labels) < 2:
        return host
    tail2 = ".".join(labels[-2:])
    tail3 = ".".join(labels[-3:]) if len(labels) >= 3 else None
    if tail2 in rules.multi_level_suffixes and tail3:
        return tail3
    return tail2


def infer_scheme(raw: str, rules: CompiledRules) -> str:
    host_port = raw.strip()
    if "://" in host_port:
        return urllib_parse.urlparse(host_port).scheme.lower() or "http"
    port = None
    if host_port.startswith("[") and "]" in host_port:
        after = host_port.split("]", 1)[1]
        if after.startswith(":"):
            try:
                port = int(after[1:])
            except ValueError:
                port = None
    elif host_port.count(":") == 1 and host_port.rsplit(":", 1)[1].isdigit():
        try:
            port = int(host_port.rsplit(":", 1)[1])
        except ValueError:
            port = None
    if port in rules.https_port_hints:
        return "https"
    return "http"


def default_port(scheme: str) -> int:
    return 443 if scheme == "https" else 80


def normalize_site_url(raw: str, rules: CompiledRules) -> Tuple[str, str, str, int]:
    candidate = raw.strip()
    if not candidate:
        raise ValueError("空行")
    if "://" not in candidate:
        candidate = f"{infer_scheme(candidate, rules)}://{candidate}"
    parsed = urllib_parse.urlparse(candidate)
    scheme = (parsed.scheme or "http").lower()
    if scheme not in {"http", "https"}:
        raise ValueError(f"不支持的协议: {scheme}")
    host = (parsed.hostname or "").strip().lower()
    if not host:
        raise ValueError(f"站点格式非法: {raw}")
    try:
        port = parsed.port or default_port(scheme)
    except ValueError as exc:
        raise ValueError(f"端口非法: {raw}") from exc
    authority = f"[{host}]" if ":" in host and not host.startswith("[") else host
    if port == default_port(scheme):
        return f"{scheme}://{authority}/", scheme, host, port
    return f"{scheme}://{authority}:{port}/", scheme, host, port


def normalize_url_for_compare(url: str) -> str:
    parsed = urllib_parse.urlparse(url)
    scheme = (parsed.scheme or "http").lower()
    host = (parsed.hostname or "").lower()
    port = parsed.port or default_port(scheme)
    authority = f"[{host}]" if ":" in host and not host.startswith("[") else host
    path = parsed.path or "/"
    query = f"?{parsed.query}" if parsed.query else ""
    if port == default_port(scheme):
        return f"{scheme}://{authority}{path}{query}"
    return f"{scheme}://{authority}:{port}{path}{query}"


def normalize_redirect_target(url: str, fallback: str) -> str:
    return normalize_url_for_compare(urllib_parse.urljoin(fallback, url))


def normalize_resource_url(page_url: str, resource_url: str) -> str:
    absolute = urllib_parse.urljoin(page_url, resource_url)
    parsed = urllib_parse.urlparse(absolute)
    page = urllib_parse.urlparse(page_url)
    path = parsed.path or "/"
    query = f"?{parsed.query}" if parsed.query else ""
    if parsed.hostname and page.hostname and parsed.hostname.lower() == page.hostname.lower():
        return f"{path}{query}"
    authority = parsed.hostname.lower() if parsed.hostname else ""
    if parsed.port and parsed.port != default_port(parsed.scheme or "http"):
        authority = f"{authority}:{parsed.port}"
    if authority:
        return f"//{authority}{path}{query}"
    return f"{path}{query}"


def is_html_content(content_type: str, body: bytes, rules: CompiledRules) -> bool:
    ctype = (content_type or "").split(";", 1)[0].strip().lower()
    if ctype in rules.html_content_types:
        return True
    sample = body[:512].lstrip().lower()
    return sample.startswith(b"<!doctype html") or sample.startswith(b"<html")


def strip_html_to_text(html_text: str) -> str:
    text = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", html_text)
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    return normalize_text(text)


def parse_html_features(page_url: str, body: bytes) -> Tuple[str, str, str, str, str, Tuple[str, ...], int, Set[str], Set[str], str]:
    html_text = body.decode("utf-8", errors="replace")
    parser = PageParser()
    parser.feed(html_text)
    title = normalize_text("".join(parser.title_parts))
    resources: Set[str] = set()
    for item in parser.resources:
        kind, _, raw_url = item.partition(":")
        resources.add(f"{kind}:{normalize_resource_url(page_url, raw_url)}")
    body_text = strip_html_to_text(html_text)
    return (
        title,
        parser.meta.get("description", ""),
        parser.meta.get("keywords", ""),
        parser.meta.get("generator", ""),
        parser.meta.get("viewport", ""),
        tuple(sorted(resources)),
        parser.non_icon_resource_count,
        parser.form_actions,
        parser.links,
        body_text,
    )


def decode_body_text(body: bytes) -> str:
    return body.decode("utf-8", errors="replace")


def normalize_response_text(text: str) -> str:
    return normalize_text(text[:4000])


def matches_any_pattern(text: str, patterns: Sequence[re.Pattern[str]]) -> bool:
    if not text:
        return False
    return any(pattern.search(text) for pattern in patterns)


def resolve_host_ips(host: str, port: int) -> Tuple[str, ...]:
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)}
    except Exception:
        return ()
    return tuple(sorted(addresses))


def base_content_type(content_type: str) -> str:
    return (content_type or "").split(";", 1)[0].strip().lower()


def normalize_shell_field_name(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", name.casefold())


def normalize_shell_scalar(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    return normalize_text(str(value)).casefold()


def xml_local_name(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", 1)[1]
    return tag


def collect_shell_json_fields(value: Any, path: Tuple[str, ...], items: List[Tuple[str, str]]) -> None:
    if isinstance(value, Mapping):
        for key in sorted(value):
            normalized_key = normalize_shell_field_name(str(key))
            collect_shell_json_fields(value[key], path + (normalized_key,), items)
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            collect_shell_json_fields(item, path + (str(index),), items)
        return
    if not path:
        return
    leaf = path[-1]
    if leaf not in SEMANTIC_SHELL_FIELD_NAMES:
        return
    items.append((".".join(path), normalize_shell_scalar(value)))


def collect_shell_xml_fields(element: ET.Element, path: Tuple[str, ...], items: List[Tuple[str, str]]) -> None:
    tag_name = normalize_shell_field_name(xml_local_name(element.tag))
    next_path = path + (tag_name,)
    children = [child for child in list(element) if isinstance(child.tag, str)]
    if not children:
        text_value = normalize_text(element.text or "")
        if text_value and tag_name in SEMANTIC_SHELL_FIELD_NAMES:
            items.append((".".join(next_path), text_value.casefold()))
        return
    for child in children:
        collect_shell_xml_fields(child, next_path, items)


def build_structured_payload_signature(content_type: str, body_text: str) -> Tuple[object, ...]:
    ctype = base_content_type(content_type)
    if not body_text:
        return ()
    if ctype in STRUCTURED_JSON_CONTENT_TYPES:
        try:
            payload = json.loads(body_text)
        except Exception:
            return ()
        items: List[Tuple[str, str]] = []
        collect_shell_json_fields(payload, tuple(), items)
        if not items:
            return ()
        return ("json", tuple(sorted(items)))
    if ctype in STRUCTURED_XML_CONTENT_TYPES:
        try:
            root = ET.fromstring(body_text)
        except Exception:
            return ()
        items: List[Tuple[str, str]] = []
        collect_shell_xml_fields(root, tuple(), items)
        if not items:
            return ()
        root_name = normalize_shell_field_name(xml_local_name(root.tag))
        return ("xml", root_name, tuple(sorted(items)))
    return ()


def body_has_business_text(text: str, rules: CompiledRules) -> bool:
    if not text:
        return False
    return bool(rules.business_text_pattern.search(text))


def detect_auth_shell(title: str, body_text: str, final_url: str, form_actions: Set[str], links: Set[str], rules: CompiledRules) -> bool:
    joined = " ".join(
        filter(
            None,
            [
                title,
                body_text[:1200],
                final_url,
                " ".join(sorted(form_actions)),
                " ".join(sorted(links)),
            ],
        )
    )
    if not joined:
        return False
    hits = sum(1 for pattern in rules.auth_shell_patterns if pattern.search(joined))
    return hits >= 2


def detect_noise(
    status_code: Optional[int],
    body_length: int,
    title: str,
    body_text: str,
    response_text: str,
    server: str,
    rules: CompiledRules,
) -> List[str]:
    reasons: List[str] = []
    title_cf = normalize_casefold(title)
    body_cf = normalize_casefold(body_text[:4000])
    response_cf = normalize_casefold(response_text[:4000])
    server_cf = normalize_casefold(server)
    if status_code in rules.small_gateway_statuses and body_length <= rules.small_gateway_body_length:
        reasons.append(NOISE_REASON_SMALL_GATEWAY)
    if any(pattern.search(title_cf) for pattern in rules.noise_title_patterns):
        reasons.append(NOISE_REASON_TITLE)
    if any(pattern.search(body_cf) for pattern in rules.noise_body_patterns):
        reasons.append(NOISE_REASON_BODY)
    if any(pattern.search(response_cf) for pattern in rules.noise_response_patterns):
        reasons.append(NOISE_REASON_RESPONSE)
    if server_cf in rules.cdn_servers and status_code in rules.cdn_statuses:
        if any(keyword in body_cf or keyword in title_cf for keyword in rules.cdn_keywords):
            reasons.append(NOISE_REASON_CDN_BLOCK)
    return sorted(set(reasons))


def detect_default_page(title: str, body_text: str, rules: CompiledRules) -> bool:
    title_cf = normalize_casefold(title)
    body_cf = normalize_casefold(body_text[:4000])
    return any(pattern.search(title_cf) or pattern.search(body_cf) for pattern in rules.default_page_patterns)


def classify_response_shell(
    status_code: Optional[int],
    content_type: str,
    title: str,
    body_text: str,
    low_information: bool,
    rules: CompiledRules,
) -> Tuple[str, str]:
    title_cf = normalize_casefold(title)
    body_cf = normalize_casefold(body_text)
    content_type_base = base_content_type(content_type)
    if matches_any_pattern(title_cf, rules.maintenance_title_patterns) or matches_any_pattern(body_cf, rules.maintenance_body_patterns):
        return "maintenance_shell", NOISE_REASON_MAINTENANCE
    if content_type in rules.auth_content_types and matches_any_pattern(body_cf, rules.auth_text_patterns):
        return "auth_api_shell", "命中统一认证/API未登录响应页"
    structured_shell_candidate = low_information and content_type_base in (STRUCTURED_XML_CONTENT_TYPES | STRUCTURED_JSON_CONTENT_TYPES)
    if (status_code in rules.deny_statuses or structured_shell_candidate) and matches_any_pattern(body_cf, rules.deny_text_patterns):
        return "deny_shell", "命中统一拒绝访问响应页"
    if low_information:
        return "low_information_shell", "命中低信息量响应页"
    return "", ""


def has_exact_shell_signals(analysis: SiteAnalysis) -> bool:
    return bool(
        analysis.shell_type
        and analysis.final_status is not None
        and analysis.content_type
        and analysis.body_sha256
        and analysis.key_path_signature
    )


def detect_low_information(body_length: int, body_text: str, non_icon_resource_count: int, resources: Sequence[str], rules: CompiledRules) -> bool:
    if body_length < rules.low_info_body_length and not body_has_business_text(body_text, rules):
        return True
    if non_icon_resource_count == 0:
        return True
    non_icon_resources = [item for item in resources if not item.startswith("icon:")]
    return len(non_icon_resources) < rules.low_info_min_non_icon_resources


def build_header_signature(headers: Dict[str, str]) -> Tuple[str, ...]:
    normalized = {key.lower(): normalize_text(value) for key, value in headers.items()}
    etag = normalized.get("etag", "")
    last_modified = normalized.get("last-modified", "")
    server = normalized.get("server", "")
    powered = normalized.get("x-powered-by", "")
    content_type = normalized.get("content-type", "").split(";", 1)[0].strip().lower()
    if etag or last_modified:
        return ("strong", etag, last_modified, server.casefold(), powered.casefold(), content_type)
    if server or powered or content_type:
        return ("weak", server.casefold(), powered.casefold(), content_type)
    return ()


def build_redirect_signature(site_url: str, final_url: str, original_status: Optional[int]) -> Tuple[str, ...]:
    site_norm = normalize_url_for_compare(site_url)
    final_norm = normalize_url_for_compare(final_url or site_url)
    if original_status and 300 <= original_status < 400 and final_norm != site_norm:
        return ("redirect", final_norm)
    return ("direct",)


def build_structure_signature(
    title: str,
    meta_description: str,
    meta_keywords: str,
    meta_generator: str,
    meta_viewport: str,
) -> Tuple[str, ...]:
    fields = (
        normalize_casefold(title),
        normalize_casefold(meta_description),
        normalize_casefold(meta_keywords),
        normalize_casefold(meta_generator),
        normalize_casefold(meta_viewport),
    )
    if not any(fields):
        return ()
    return fields


def build_key_path_signature(probes: Sequence[PathProbe]) -> Tuple[Tuple[str, Optional[int], str, str, str, str], ...]:
    return tuple(
        (
            probe.path,
            probe.status_code,
            probe.body_sha256,
            probe.content_type,
            probe.etag,
            probe.last_modified,
        )
        for probe in sorted(probes, key=lambda item: item.path)
    )


def build_shell_merge_key_path_signature(probes: Sequence[PathProbe]) -> Tuple[Tuple[object, ...], ...]:
    return tuple(
        (
            probe.path,
            probe.status_code,
            probe.content_type,
            probe.merge_signature if probe.merge_signature else probe.body_sha256,
            probe.error,
        )
        for probe in sorted(probes, key=lambda item: item.path)
    )


def build_shell_merge_fingerprint(analysis: SiteAnalysis) -> Tuple[object, ...]:
    if not analysis.shell_exact_fingerprint:
        return ()
    if analysis.shell_type not in {"deny_shell", "auth_api_shell"}:
        return analysis.shell_exact_fingerprint
    payload_signature = build_structured_payload_signature(analysis.content_type, analysis.response_text_excerpt)
    if not payload_signature:
        payload_signature = ("raw_sha256", analysis.body_sha256)
    key_path_signature = build_shell_merge_key_path_signature(analysis.key_paths)
    return (
        analysis.shell_type,
        analysis.final_status,
        analysis.content_type,
        normalize_casefold(analysis.server),
        payload_signature,
        key_path_signature,
    )


def should_retry_exception(exc: Exception) -> bool:
    message = str(exc).lower()
    non_retry_keywords = (
        "certificate verify failed",
        "hostname mismatch",
        "self-signed certificate",
        "unable to get local issuer certificate",
        "wrong version number",
        "tlsv1 alert",
        "sslv3 alert",
    )
    if any(keyword in message for keyword in non_retry_keywords):
        return False
    return True


def classify_probe_error(error_message: str) -> str:
    message = error_message.lower()
    if "certificate verify failed" in message or "hostname mismatch" in message or "ssl" in message:
        return "SSL证书校验失败"
    if "proxyerror" in message or "unable to connect to proxy" in message or "proxy" in message:
        return "代理连接失败"
    if "timed out" in message or "read timeout" in message or "connect timeout" in message:
        return "请求超时"
    if "nodename nor servname" in message or "name or service not known" in message or "temporary failure in name resolution" in message:
        return "DNS解析失败"
    if "connection refused" in message:
        return "连接被拒绝"
    if "remote end closed connection without response" in message:
        return "远端直接关闭连接"
    if "connection reset" in message or "connection aborted" in message:
        return "连接被重置或中断"
    return "其他请求失败"


def fetch_with_urllib(
    url: str,
    allow_redirects: bool,
    timeout: float,
    insecure: bool,
    max_body_bytes: int,
    user_agent: str,
    use_env_proxy: bool,
) -> Tuple[str, int, Dict[str, str], bytes]:
    context = ssl._create_unverified_context() if insecure else None
    handlers = []
    if not use_env_proxy:
        handlers.append(urllib_request.ProxyHandler({}))
    if context is not None:
        handlers.append(urllib_request.HTTPSHandler(context=context))
    if not allow_redirects:
        handlers.append(NoRedirectHandler())
    opener = urllib_request.build_opener(*handlers)
    req = urllib_request.Request(url, headers={"User-Agent": user_agent})
    try:
        with opener.open(req, timeout=timeout) as response:
            body = response.read(max_body_bytes + 1)[:max_body_bytes]
            return response.geturl(), response.getcode(), dict(response.headers.items()), body
    except urllib_error.HTTPError as exc:
        body = exc.read(max_body_bytes + 1)[:max_body_bytes]
        return exc.geturl(), exc.code, dict(exc.headers.items()), body


def fetch_with_requests(
    url: str,
    allow_redirects: bool,
    timeout: float,
    insecure: bool,
    max_body_bytes: int,
    user_agent: str,
    use_env_proxy: bool,
) -> Tuple[str, int, Dict[str, str], bytes]:
    with requests.Session() as session:  # type: ignore[union-attr]
        session.trust_env = use_env_proxy
        response = session.get(
            url,
            allow_redirects=allow_redirects,
            timeout=timeout,
            verify=not insecure,
            headers={"User-Agent": user_agent},
        )
    return response.url, response.status_code, dict(response.headers.items()), response.content[:max_body_bytes]


def fetch_url(url: str, allow_redirects: bool, timeout: float, insecure: bool, rules: CompiledRules) -> Tuple[str, int, Dict[str, str], bytes]:
    last_error: Optional[Exception] = None
    total_attempts = max(1, rules.retry_attempts + 1)
    for attempt in range(1, total_attempts + 1):
        try:
            if requests is not None:
                return fetch_with_requests(
                    url=url,
                    allow_redirects=allow_redirects,
                    timeout=timeout,
                    insecure=insecure,
                    max_body_bytes=rules.max_body_bytes,
                    user_agent=rules.user_agent,
                    use_env_proxy=rules.use_env_proxy,
                )
            return fetch_with_urllib(
                url=url,
                allow_redirects=allow_redirects,
                timeout=timeout,
                insecure=insecure,
                max_body_bytes=rules.max_body_bytes,
                user_agent=rules.user_agent,
                use_env_proxy=rules.use_env_proxy,
            )
        except Exception as exc:
            last_error = exc
            if attempt >= total_attempts or not should_retry_exception(exc):
                raise
            sleep_seconds = rules.retry_backoff_seconds * attempt
            if sleep_seconds > 0:
                time.sleep(sleep_seconds)
    assert last_error is not None
    raise last_error


def canonical_origin(url: str) -> str:
    parsed = urllib_parse.urlparse(url)
    scheme = (parsed.scheme or "http").lower()
    host = (parsed.hostname or "").lower()
    port = parsed.port or default_port(scheme)
    authority = f"[{host}]" if ":" in host and not host.startswith("[") else host
    if port == default_port(scheme):
        return f"{scheme}://{authority}"
    return f"{scheme}://{authority}:{port}"


def probe_key_paths(site: SiteInput, timeout: float, insecure: bool, rules: CompiledRules) -> Tuple[PathProbe, ...]:
    origin = site.url.rstrip("/")
    results: List[PathProbe] = []
    for path in rules.key_paths:
        try:
            _, status, headers, body = fetch_url(f"{origin}{path}", True, timeout, insecure, rules)
            normalized = {key.lower(): normalize_text(value) for key, value in headers.items()}
            content_type = base_content_type(normalized.get("content-type", ""))
            body_text = decode_body_text(body)
            results.append(
                PathProbe(
                    path=path,
                    status_code=status,
                    body_sha256=sha256_hex(body),
                    content_type=content_type,
                    etag=normalized.get("etag", ""),
                    last_modified=normalized.get("last-modified", ""),
                    merge_signature=build_structured_payload_signature(content_type, body_text),
                )
            )
        except Exception as exc:
            results.append(
                PathProbe(
                    path=path,
                    status_code=None,
                    body_sha256="",
                    content_type="",
                    etag="",
                    last_modified="",
                    error=str(exc),
                )
            )
    return tuple(results)


def parse_site_line(raw: str, rules: CompiledRules) -> Optional[SiteInput]:
    line = raw.strip()
    if not line or line.startswith("#"):
        return None
    url, scheme, host, port = normalize_site_url(line, rules)
    return SiteInput(
        raw=line,
        url=url,
        scheme=scheme,
        host=host,
        port=port,
        is_ip=is_ip_literal(host),
        registrable_domain=get_registrable_domain(host, rules),
    )


def analyze_site(site: SiteInput, timeout: float, insecure: bool, rules: CompiledRules) -> SiteAnalysis:
    analysis = SiteAnalysis(site=site)
    try:
        analysis.resolved_ips = resolve_host_ips(site.host, site.port)
        first_url, first_status, first_headers, first_body = fetch_url(site.url, False, timeout, insecure, rules)
        first_headers_normalized = {key.lower(): normalize_text(value) for key, value in first_headers.items()}
        analysis.original_status = first_status
        redirect_target = first_headers_normalized.get("location", "")
        if redirect_target:
            analysis.redirect_target = normalize_redirect_target(redirect_target, first_url)
        if redirect_target and 300 <= first_status < 400:
            final_url, final_status, final_headers, final_body = fetch_url(site.url, True, timeout, insecure, rules)
        else:
            final_url, final_status, final_headers, final_body = first_url, first_status, first_headers, first_body
        final_headers_normalized = {key.lower(): normalize_text(value) for key, value in final_headers.items()}
        analysis.final_status = final_status
        analysis.final_url = final_url
        analysis.final_url_normalized = normalize_url_for_compare(final_url or site.url)
        analysis.final_origin = canonical_origin(final_url or site.url)
        analysis.body_length = len(final_body)
        analysis.body_sha256 = sha256_hex(final_body)
        analysis.etag = final_headers_normalized.get("etag", "")
        analysis.last_modified = final_headers_normalized.get("last-modified", "")
        analysis.server = final_headers_normalized.get("server", "")
        analysis.x_powered_by = final_headers_normalized.get("x-powered-by", "")
        analysis.content_type = final_headers_normalized.get("content-type", "").split(";", 1)[0].strip().lower()
        response_text = normalize_response_text(decode_body_text(final_body))
        analysis.response_text_excerpt = response_text
        if is_html_content(analysis.content_type, final_body, rules):
            (
                analysis.title,
                analysis.meta_description,
                analysis.meta_keywords,
                analysis.meta_generator,
                analysis.meta_viewport,
                analysis.resources,
                analysis.non_icon_resource_count,
                form_actions,
                links,
                body_text,
            ) = parse_html_features(final_url or site.url, final_body)
        else:
            form_actions = set()
            links = set()
            body_text = response_text
        analysis.body_text_excerpt = body_text[:4000]
        analysis.noise_reasons = tuple(
            detect_noise(
                status_code=analysis.final_status,
                body_length=analysis.body_length,
                title=analysis.title,
                body_text=body_text,
                response_text=response_text,
                server=analysis.server,
                rules=rules,
            )
        )
        analysis.default_page_hit = detect_default_page(
            title=analysis.title,
            body_text=body_text,
            rules=rules,
        )
        analysis.low_information = detect_low_information(
            body_length=analysis.body_length,
            body_text=body_text,
            non_icon_resource_count=analysis.non_icon_resource_count,
            resources=analysis.resources,
            rules=rules,
        )
        if analysis.default_page_hit:
            analysis.low_information = True
        analysis.auth_shell_like = detect_auth_shell(
            title=analysis.title,
            body_text=body_text,
            final_url=analysis.final_url_normalized,
            form_actions=form_actions,
            links=links,
            rules=rules,
        )
        analysis.shell_type, analysis.shell_reason = classify_response_shell(
            status_code=analysis.final_status,
            content_type=analysis.content_type,
            title=analysis.title,
            body_text=response_text or body_text,
            low_information=analysis.low_information,
            rules=rules,
        )
        if analysis.shell_type == "maintenance_shell":
            analysis.noise_reasons = tuple(sorted(set(analysis.noise_reasons + (NOISE_REASON_MAINTENANCE,))))
        analysis.key_paths = probe_key_paths(site, timeout, insecure, rules)
        analysis.header_signature = build_header_signature(final_headers)
        analysis.redirect_signature = build_redirect_signature(site.url, analysis.final_url or site.url, analysis.original_status)
        analysis.structure_signature = build_structure_signature(
            analysis.title,
            analysis.meta_description,
            analysis.meta_keywords,
            analysis.meta_generator,
            analysis.meta_viewport,
        )
        analysis.resource_signature = analysis.resources
        analysis.key_path_signature = build_key_path_signature(analysis.key_paths)
        analysis.comparison_ready = all(
            (
                analysis.header_signature,
                analysis.redirect_signature,
                analysis.structure_signature,
                analysis.resource_signature,
                analysis.key_path_signature,
            )
        )
        if analysis.comparison_ready:
            analysis.equivalence_fingerprint = (
                analysis.header_signature,
                analysis.redirect_signature,
                analysis.structure_signature,
                analysis.resource_signature,
                analysis.key_path_signature,
            )
        if has_exact_shell_signals(analysis):
            analysis.shell_exact_fingerprint = (
                analysis.shell_type,
                analysis.final_status,
                analysis.content_type,
                analysis.body_sha256,
                analysis.key_path_signature,
            )
            analysis.shell_merge_fingerprint = build_shell_merge_fingerprint(analysis)
        return analysis
    except Exception as exc:
        analysis.probe_error = str(exc)
        return analysis


def choose_representative(urls: Sequence[str], analyses: Dict[str, SiteAnalysis]) -> str:
    def score(url: str) -> Tuple[int, int, int, int, str]:
        analysis = analyses[url]
        redirect_rank = 1 if analysis.redirect_signature[:1] == ("redirect",) else 0
        https_rank = 0 if analysis.site.scheme == "https" else 1
        port_rank = 0 if analysis.site.port == 443 else 1
        ip_rank = 1 if analysis.site.is_ip else 0
        return (redirect_rank, https_rank, port_rank, ip_rank, url)

    return min(urls, key=score)


def collect_redirect_merges(analyses: Dict[str, SiteAnalysis], active_urls: Set[str], uf: UnionFind, external_groups: List[MergeGroup]) -> None:
    by_url = set(analyses)
    for url, analysis in analyses.items():
        if url not in active_urls:
            continue
        if analysis.noise_reasons or analysis.probe_error:
            continue
        if analysis.original_status is None or not (300 <= analysis.original_status < 400):
            continue
        if not analysis.redirect_target:
            continue
        source = urllib_parse.urlparse(url)
        target = urllib_parse.urlparse(analysis.redirect_target)
        if source.scheme != "http" or target.scheme != "https":
            continue
        if (source.hostname or "").lower() != (target.hostname or "").lower():
            continue
        if analysis.redirect_target in by_url and analysis.redirect_target in active_urls:
            uf.union(url, analysis.redirect_target)
        else:
            external_groups.append(
                MergeGroup(
                    group_type=GROUP_TYPE_HTTP_HTTPS,
                    representative=analysis.redirect_target,
                    members=[url],
                    reason=MERGE_REASON_HTTP_HTTPS,
                )
            )
            active_urls.discard(url)


def group_by_fingerprint(urls: Sequence[str], analyses: Dict[str, SiteAnalysis]) -> Dict[Tuple[object, ...], List[str]]:
    grouped: Dict[Tuple[object, ...], List[str]] = {}
    for url in urls:
        fingerprint = analyses[url].equivalence_fingerprint
        if fingerprint:
            grouped.setdefault(fingerprint, []).append(url)
    return grouped


def collect_equivalent_merges(analyses: Dict[str, SiteAnalysis], active_urls: Set[str], uf: UnionFind) -> None:
    by_host: Dict[str, List[str]] = {}
    for url in active_urls:
        analysis = analyses[url]
        if (
            analysis.noise_reasons
            or analysis.probe_error
            or analysis.auth_shell_like
            or not analysis.comparison_ready
            or analysis.shell_type
        ):
            continue
        by_host.setdefault(analysis.site.host, []).append(url)
    for urls in by_host.values():
        if len(urls) < 2:
            continue
        for same_fp_urls in group_by_fingerprint(urls, analyses).values():
            if len(same_fp_urls) < 2:
                continue
            anchor = same_fp_urls[0]
            for other in same_fp_urls[1:]:
                uf.union(anchor, other)

    by_reg_domain: Dict[str, List[str]] = {}
    for url in active_urls:
        analysis = analyses[url]
        reg_domain = analysis.site.registrable_domain
        if not reg_domain:
            continue
        if analysis.site.is_ip or analysis.noise_reasons or analysis.probe_error:
            continue
        if analysis.low_information or analysis.auth_shell_like or not analysis.comparison_ready or analysis.shell_type:
            continue
        by_reg_domain.setdefault(reg_domain, []).append(url)
    for urls in by_reg_domain.values():
        if len(urls) < 2:
            continue
        for same_fp_urls in group_by_fingerprint(urls, analyses).values():
            if len(same_fp_urls) < 2:
                continue
            hosts = {analyses[url].site.host for url in same_fp_urls}
            if len(hosts) < 2:
                continue
            anchor = same_fp_urls[0]
            for other in same_fp_urls[1:]:
                uf.union(anchor, other)

    by_ip_port_fp: Dict[Tuple[Tuple[str, ...], int, Optional[int], str, Tuple[object, ...]], List[str]] = {}
    for url in active_urls:
        analysis = analyses[url]
        if analysis.site.is_ip or analysis.noise_reasons or analysis.probe_error:
            continue
        if analysis.low_information or analysis.auth_shell_like or not analysis.comparison_ready or analysis.shell_type:
            continue
        if not analysis.resolved_ips or not analysis.body_sha256:
            continue
        key = (
            analysis.resolved_ips,
            analysis.site.port,
            analysis.final_status,
            analysis.body_sha256,
            analysis.equivalence_fingerprint,
        )
        by_ip_port_fp.setdefault(key, []).append(url)
    for urls in by_ip_port_fp.values():
        if len(urls) < 2:
            continue
        reg_domains = {analyses[url].site.registrable_domain for url in urls}
        hosts = {analyses[url].site.host for url in urls}
        if None in reg_domains or len(reg_domains) < 2 or len(hosts) < 2:
            continue
        anchor = urls[0]
        for other in urls[1:]:
            uf.union(anchor, other)


def collect_same_host_shell_results(
    analyses: Dict[str, SiteAnalysis], candidate_urls: Set[str]
) -> Tuple[List[MergeGroup], Dict[str, Set[str]], Set[str]]:
    merge_groups: List[MergeGroup] = []
    noise_reason_map: Dict[str, Set[str]] = {}
    consumed_urls: Set[str] = set()
    by_host_fingerprint: Dict[Tuple[str, Tuple[object, ...]], List[str]] = {}

    for url in candidate_urls:
        analysis = analyses[url]
        if analysis.probe_error or not analysis.shell_merge_fingerprint:
            continue
        if analysis.shell_type not in {"deny_shell", "auth_api_shell", "low_information_shell"}:
            continue
        if analysis.site.is_ip:
            continue
        key = (analysis.site.host, analysis.shell_merge_fingerprint)
        by_host_fingerprint.setdefault(key, []).append(url)

    for urls in by_host_fingerprint.values():
        ports = {analyses[url].site.port for url in urls}
        if len(urls) < 2 or len(ports) < 2:
            continue
        members = sorted(urls)
        shell_type = analyses[members[0]].shell_type
        consumed_urls.update(members)
        if shell_type == "deny_shell":
            for url in members:
                noise_reason_map.setdefault(url, set()).add(NOISE_REASON_SAME_HOST_DENY)
            continue
        merge_groups.append(
            MergeGroup(
                group_type=GROUP_TYPE_SAME_HOST_SHELL,
                representative=choose_representative(members, analyses),
                members=members,
                reason=MERGE_REASON_SAME_HOST_SHELL,
            )
        )

    return merge_groups, noise_reason_map, consumed_urls


def collect_same_port_subdomain_shell_results(
    analyses: Dict[str, SiteAnalysis], candidate_urls: Set[str]
) -> Tuple[List[MergeGroup], Set[str]]:
    merge_groups: List[MergeGroup] = []
    consumed_urls: Set[str] = set()
    grouped: Dict[Tuple[str, int, Tuple[str, ...], Tuple[object, ...]], List[str]] = {}

    for url in candidate_urls:
        analysis = analyses[url]
        reg_domain = analysis.site.registrable_domain
        if analysis.probe_error or not analysis.shell_merge_fingerprint:
            continue
        if analysis.shell_type not in {"deny_shell", "auth_api_shell", "low_information_shell"}:
            continue
        if analysis.site.is_ip or not reg_domain or not analysis.resolved_ips:
            continue
        key = (
            reg_domain,
            analysis.site.port,
            analysis.resolved_ips,
            analysis.shell_merge_fingerprint,
        )
        grouped.setdefault(key, []).append(url)

    for urls in grouped.values():
        hosts = {analyses[url].site.host for url in urls}
        if len(urls) < 2 or len(hosts) < 2:
            continue
        members = sorted(urls)
        consumed_urls.update(members)
        merge_groups.append(
            MergeGroup(
                group_type=GROUP_TYPE_SAME_PORT_SUBDOMAIN_SHELL,
                representative=choose_representative(members, analyses),
                members=members,
                reason=MERGE_REASON_SAME_PORT_SUBDOMAIN_SHELL,
            )
        )

    return merge_groups, consumed_urls


def build_output(analyses: Dict[str, SiteAnalysis], external_groups: List[MergeGroup]) -> Dict[str, object]:
    noise_sites = []
    noise_reason_map: Dict[str, Set[str]] = {
        url: set(analysis.noise_reasons)
        for url, analysis in analyses.items()
        if analysis.noise_reasons
    }

    shell_candidate_urls = {
        url
        for url, analysis in analyses.items()
        if not analysis.probe_error and not noise_reason_map.get(url)
    }
    same_host_shell_groups, same_host_shell_noise, same_host_shell_consumed = collect_same_host_shell_results(
        analyses, shell_candidate_urls
    )
    for url, reasons in same_host_shell_noise.items():
        noise_reason_map.setdefault(url, set()).update(reasons)

    same_port_shell_groups, same_port_shell_consumed = collect_same_port_subdomain_shell_results(
        analyses,
        {
            url
            for url in shell_candidate_urls
            if url not in same_host_shell_consumed and not same_host_shell_noise.get(url)
        },
    )
    shell_consumed_urls = same_host_shell_consumed | same_port_shell_consumed

    active_urls = {
        url
        for url in analyses
        if url not in shell_consumed_urls and not noise_reason_map.get(url)
    }
    uf = UnionFind(active_urls)
    collect_redirect_merges(analyses, active_urls, uf, external_groups)
    collect_equivalent_merges(analyses, active_urls, uf)

    merge_groups: List[MergeGroup] = []
    grouped_urls: Set[str] = set()
    merge_groups.extend(same_host_shell_groups)
    merge_groups.extend(same_port_shell_groups)
    for group in same_host_shell_groups + same_port_shell_groups:
        grouped_urls.update(group.members)

    for urls in uf.groups().values():
        if len(urls) < 2:
            continue
        representative = choose_representative(urls, analyses)
        hosts = {analyses[url].site.host for url in urls}
        has_redirect_edge = any(
            analyses[url].redirect_signature[:1] == ("redirect",)
            and analyses[url].redirect_signature[1] == normalize_url_for_compare(representative)
            for url in urls
            if url != representative
        )
        if has_redirect_edge and len(urls) == 2 and len(hosts) == 1:
            group_type = GROUP_TYPE_HTTP_HTTPS
            reason = MERGE_REASON_HTTP_HTTPS
        elif len(hosts) == 1:
            group_type = GROUP_TYPE_SAME_HOST
            reason = MERGE_REASON_SAME_HOST_WITH_REDIRECT if has_redirect_edge else MERGE_REASON_SAME_HOST
        elif len({analyses[url].site.registrable_domain for url in urls}) > 1:
            group_type = GROUP_TYPE_SAME_IP_CROSS_DOMAIN
            reason = MERGE_REASON_SAME_IP_CROSS_DOMAIN
        else:
            group_type = GROUP_TYPE_SAME_DOMAIN
            reason = MERGE_REASON_SAME_DOMAIN
        merge_groups.append(
            MergeGroup(
                group_type=group_type,
                representative=representative,
                members=sorted(urls),
                reason=reason,
            )
        )
        grouped_urls.update(urls)

    merge_groups.extend(external_groups)
    for group in external_groups:
        grouped_urls.update(group.members)

    independent_sites = []
    for url, analysis in analyses.items():
        combined_noise_reasons = sorted(noise_reason_map.get(url, set()))
        if combined_noise_reasons:
            noise_sites.append(
                {
                    "url": url,
                    "reasons": combined_noise_reasons,
                    "title": analysis.title,
                    "status_code": analysis.final_status,
                }
            )
            continue
        if url in grouped_urls:
            continue
        reason = INDEPENDENT_REASON_DEFAULT
        if analysis.probe_error:
            reason = INDEPENDENT_REASON_PROBE_FAILED
        elif analysis.site.is_ip:
            reason = INDEPENDENT_REASON_IP_DIRECT
        elif analysis.low_information:
            reason = INDEPENDENT_REASON_LOW_INFO
        elif analysis.auth_shell_like:
            reason = INDEPENDENT_REASON_AUTH_SHELL
        elif not analysis.comparison_ready:
            reason = INDEPENDENT_REASON_SIGNALS_WEAK
        independent_sites.append(
            {
                "url": url,
                "reason": reason,
                "title": analysis.title,
                "status_code": analysis.final_status,
            }
        )

    details = {}
    failure_categories: Dict[str, List[str]] = {}
    for url, analysis in analyses.items():
        combined_noise_reasons = sorted(noise_reason_map.get(url, set()))
        if analysis.probe_error:
            category = classify_probe_error(analysis.probe_error)
            failure_categories.setdefault(category, []).append(url)
        details[url] = {
            "raw": analysis.site.raw,
            "probe_error": analysis.probe_error,
            "original_status": analysis.original_status,
            "final_status": analysis.final_status,
            "final_url": analysis.final_url_normalized,
            "title": analysis.title,
            "meta_description": analysis.meta_description,
            "meta_keywords": analysis.meta_keywords,
            "meta_generator": analysis.meta_generator,
            "meta_viewport": analysis.meta_viewport,
            "server": analysis.server,
            "etag": analysis.etag,
            "last_modified": analysis.last_modified,
            "content_type": analysis.content_type,
            "body_length": analysis.body_length,
            "body_sha256": analysis.body_sha256,
            "body_text_excerpt": analysis.body_text_excerpt,
            "response_text_excerpt": analysis.response_text_excerpt,
            "resources": list(analysis.resources),
            "noise_reasons": combined_noise_reasons,
            "default_page_hit": analysis.default_page_hit,
            "low_information": analysis.low_information,
            "auth_shell_like": analysis.auth_shell_like,
            "shell_type": analysis.shell_type,
            "shell_reason": analysis.shell_reason,
            "resolved_ips": list(analysis.resolved_ips),
            "comparison_ready": analysis.comparison_ready,
            "key_paths": [asdict(item) for item in analysis.key_paths],
        }

    merge_member_count = sum(len(group.members) for group in merge_groups)
    probe_failed_count = sum(1 for analysis in analyses.values() if analysis.probe_error)
    failure_summary = [
        {
            "category": category,
            "count": len(urls),
            "sample_urls": sorted(urls)[:5],
        }
        for category, urls in sorted(failure_categories.items(), key=lambda item: (-len(item[1]), item[0]))
    ]
    summary = {
        "输入站点数": len(analyses),
        "探测失败数": probe_failed_count,
        "噪音站点数": len(noise_sites),
        "可合并站点组数": len(merge_groups),
        "可合并站点成员数": merge_member_count,
        "独立站点数": len(independent_sites),
    }
    return {
        "summary": summary,
        "failure_summary": failure_summary,
        "noise_sites": sorted(noise_sites, key=lambda item: item["url"]),
        "merge_groups": [
            {
                "group_type": group.group_type,
                "representative": group.representative,
                "member_count": len(group.members),
                "members": group.members,
                "reason": group.reason,
            }
            for group in sorted(merge_groups, key=lambda item: (item.group_type, item.representative))
        ],
        "independent_sites": sorted(independent_sites, key=lambda item: item["url"]),
        "details": details,
    }


def shorten_urls(urls: Sequence[str], sample_limit: int) -> str:
    if not urls:
        return "无"
    if len(urls) <= sample_limit:
        return "，".join(urls)
    head = "，".join(urls[:sample_limit])
    return f"{head} ...（其余 {len(urls) - sample_limit} 个省略）"


def format_duration(seconds: float) -> str:
    total_ms = int(round(seconds * 1000))
    hours, rem_ms = divmod(total_ms, 3600 * 1000)
    minutes, rem_ms = divmod(rem_ms, 60 * 1000)
    secs, millis = divmod(rem_ms, 1000)
    if hours > 0:
        return f"{hours}小时{minutes}分{secs}秒"
    if minutes > 0:
        return f"{minutes}分{secs}秒"
    if secs > 0:
        return f"{secs}.{millis:03d}秒"
    return f"{millis}毫秒"


def print_summary_report_plain(result: Dict[str, object], sample_limit: int) -> None:
    summary = result["summary"]
    failure_summary = result.get("failure_summary", [])
    noise_sites = result["noise_sites"]
    merge_groups = result["merge_groups"]
    independent_sites = result["independent_sites"]

    print("结果概要")
    print(f"- 输入站点数: {summary['输入站点数']}")
    print(f"- 使用并发数: {summary['使用并发数']}")
    print(f"- 任务耗时: {summary['任务耗时']}")
    print(f"- 探测失败数: {summary['探测失败数']}")
    print(f"- 噪音站点数: {summary['噪音站点数']}")
    print(f"- 可合并站点组数: {summary['可合并站点组数']}")
    print(f"- 可合并站点成员数: {summary['可合并站点成员数']}")
    print(f"- 独立站点数: {summary['独立站点数']}")
    print()

    print("失败原因概要")
    if not failure_summary:
        print("- 无")
    else:
        for item in failure_summary[:sample_limit]:
            samples = shorten_urls(item["sample_urls"], sample_limit)
            print(f"- {item['category']}: {item['count']} 个")
            print(f"  示例: {samples}")
        if len(failure_summary) > sample_limit:
            print(f"- 其余 {len(failure_summary) - sample_limit} 类失败原因省略")
    print()

    print("噪音站点示例")
    if not noise_sites:
        print("- 无")
    else:
        for item in noise_sites[:sample_limit]:
            reasons = "；".join(item["reasons"])
            print(f"- {item['url']} [{item['status_code']}] {reasons}")
        if len(noise_sites) > sample_limit:
            print(f"- 其余 {len(noise_sites) - sample_limit} 个噪音站点省略")
    print()

    print("可合并站点组概要")
    if not merge_groups:
        print("- 无")
    else:
        for group in merge_groups[:sample_limit]:
            samples = shorten_urls(group["members"], sample_limit)
            print(f"- 类型: {group['group_type']}")
            print(f"  代表站点: {group['representative']}")
            print(f"  成员数: {group['member_count']}")
            print(f"  成员示例: {samples}")
            print(f"  原因: {group['reason']}")
        if len(merge_groups) > sample_limit:
            print(f"- 其余 {len(merge_groups) - sample_limit} 个合并组省略")
    print()

    print("独立站点示例")
    if not independent_sites:
        print("- 无")
    else:
        for item in independent_sites[:sample_limit]:
            print(f"- {item['url']} [{item['status_code']}] {item['reason']}")
        if len(independent_sites) > sample_limit:
            print(f"- 其余 {len(independent_sites) - sample_limit} 个独立站点省略")


def build_rich_table(
    title: str,
    columns: Sequence[Tuple[str, str]],
    rows: Sequence[Sequence[object]],
    empty_text: str,
) -> "Table":
    table = Table(
        title=title,
        box=box.ROUNDED,
        show_lines=False,
        header_style="bold cyan",
        title_style="bold white",
        expand=True,
    )
    for header, justify in columns:
        kwargs: Dict[str, object] = {"justify": justify}
        if header in {"URL", "代表站点", "成员示例", "示例", "原因"}:
            kwargs["overflow"] = "fold"
        table.add_column(header, **kwargs)

    if rows:
        for row in rows:
            rendered = []
            for cell in row:
                if cell is None:
                    rendered.append("-")
                else:
                    rendered.append(str(cell))
            table.add_row(*rendered)
    else:
        table.add_row(empty_text, *("" for _ in range(max(0, len(columns) - 1))))
    return table


def print_summary_report_rich(result: Dict[str, object], sample_limit: int) -> None:
    summary = result["summary"]
    failure_summary = result.get("failure_summary", [])
    noise_sites = result["noise_sites"]
    merge_groups = result["merge_groups"]
    independent_sites = result["independent_sites"]

    console = Console(highlight=False, soft_wrap=True)

    summary_table = Table(box=box.SIMPLE_HEAVY, show_header=False, expand=False, pad_edge=False)
    summary_table.add_column("指标", style="bold cyan")
    summary_table.add_column("值", style="bold white")
    summary_table.add_row("输入站点数", str(summary["输入站点数"]))
    summary_table.add_row("使用并发数", str(summary["使用并发数"]))
    summary_table.add_row("任务耗时", str(summary["任务耗时"]))
    summary_table.add_row("探测失败数", str(summary["探测失败数"]))
    summary_table.add_row("噪音站点数", str(summary["噪音站点数"]))
    summary_table.add_row("可合并站点组数", str(summary["可合并站点组数"]))
    summary_table.add_row("可合并站点成员数", str(summary["可合并站点成员数"]))
    summary_table.add_row("独立站点数", str(summary["独立站点数"]))
    console.print(Panel(summary_table, title="结果概要", border_style="blue"))

    failure_rows = [
        (
            item["category"],
            f"{item['count']} 个",
            shorten_urls(item["sample_urls"], sample_limit),
        )
        for item in failure_summary[:sample_limit]
    ]
    if len(failure_summary) > sample_limit:
        failure_rows.append((f"其余 {len(failure_summary) - sample_limit} 类", "-", "省略"))
    console.print(
        build_rich_table(
            "失败原因概要",
            [("类别", "left"), ("数量", "right"), ("示例", "left")],
            failure_rows,
            "无",
        )
    )

    noise_rows = [
        (
            item["url"],
            item["status_code"] if item["status_code"] is not None else "-",
            "；".join(item["reasons"]),
        )
        for item in noise_sites[:sample_limit]
    ]
    if len(noise_sites) > sample_limit:
        noise_rows.append((f"其余 {len(noise_sites) - sample_limit} 个噪音站点", "-", "省略"))
    console.print(
        build_rich_table(
            "噪音站点示例",
            [("URL", "left"), ("状态", "right"), ("原因", "left")],
            noise_rows,
            "无",
        )
    )

    merge_rows = [
        (
            group["group_type"],
            group["representative"],
            group["member_count"],
            shorten_urls(group["members"], sample_limit),
            group["reason"],
        )
        for group in merge_groups[:sample_limit]
    ]
    if len(merge_groups) > sample_limit:
        merge_rows.append((f"其余 {len(merge_groups) - sample_limit} 个合并组", "-", "-", "省略", "-"))
    console.print(
        build_rich_table(
            "可合并站点组概要",
            [("类型", "left"), ("代表站点", "left"), ("成员数", "right"), ("成员示例", "left"), ("原因", "left")],
            merge_rows,
            "无",
        )
    )

    independent_rows = [
        (
            item["url"],
            item["status_code"] if item["status_code"] is not None else "-",
            item["reason"],
        )
        for item in independent_sites[:sample_limit]
    ]
    if len(independent_sites) > sample_limit:
        independent_rows.append((f"其余 {len(independent_sites) - sample_limit} 个独立站点", "-", "省略"))
    console.print(
        build_rich_table(
            "独立站点示例",
            [("URL", "left"), ("状态", "right"), ("原因", "left")],
            independent_rows,
            "无",
        )
    )


def print_summary_report(result: Dict[str, object], sample_limit: int) -> None:
    if RICH_AVAILABLE:
        print_summary_report_rich(result, sample_limit)
        return
    print_summary_report_plain(result, sample_limit)


def render_progress(done: int, total: int, failed: int) -> None:
    if total <= 0:
        return
    percent = done * 100.0 / total
    ok = done - failed
    sys.stderr.write(f"\r进度: {done}/{total} ({percent:5.1f}%) | 成功: {ok} | 失败: {failed}")
    sys.stderr.flush()
    if done == total:
        sys.stderr.write("\n")
        sys.stderr.flush()


def load_sites(path: Path, rules: CompiledRules) -> List[SiteInput]:
    sites: List[SiteInput] = []
    seen: Set[str] = set()
    with path.open("r", encoding="utf-8") as handle:
        for line_number, raw in enumerate(handle, start=1):
            try:
                site = parse_site_line(raw, rules)
            except ValueError as exc:
                raise ValueError(f"{path}:{line_number}: {exc}") from exc
            if not site:
                continue
            if site.url in seen:
                continue
            seen.add(site.url)
            sites.append(site)
    return sites


def analyze_sites(sites: Sequence[SiteInput], timeout: float, insecure: bool, workers: int, rules: CompiledRules, show_progress: bool) -> Dict[str, SiteAnalysis]:
    analyses: Dict[str, SiteAnalysis] = {}
    total = len(sites)
    done = 0
    failed = 0
    if show_progress:
        render_progress(done, total, failed)
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        future_map = {
            executor.submit(analyze_site, site, timeout, insecure, rules): site.url
            for site in sites
        }
        for future in concurrent.futures.as_completed(future_map):
            url = future_map[future]
            analysis = future.result()
            analyses[url] = analysis
            done += 1
            if analysis.probe_error:
                failed += 1
            if show_progress:
                render_progress(done, total, failed)
    return analyses


def default_rules_path() -> Path:
    return Path(__file__).resolve().with_name(RULES_FILE_NAME)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="按安全视角方案识别站点中的独立站、可合并站点和噪音站点")
    parser.add_argument("-f", "--file", required=True, help="输入文件，一行一个站点")
    parser.add_argument("-o", "--output", help="可选，输出完整 JSON 结果文件")
    parser.add_argument("--rules", default=str(default_rules_path()), help="规则文件路径，默认读取脚本同目录下的 YAML")
    parser.add_argument("--timeout", type=float, help="HTTP 超时时间，默认取规则文件中的 default_timeout")
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS, help=f"并发数，默认 {DEFAULT_WORKERS}")
    parser.add_argument("--insecure", action="store_true", help="关闭 HTTPS 证书校验；当前已是默认行为，保留兼容")
    parser.add_argument("--verify-tls", action="store_true", help="开启 HTTPS 证书校验")
    parser.add_argument("--retries", type=int, help="失败后的重试次数，默认取规则文件中的 retry_attempts")
    parser.add_argument("--user-agent", help="覆盖默认请求 User-Agent")
    parser.add_argument("--use-env-proxy", action="store_true", help="启用环境变量中的代理设置，默认关闭")
    parser.add_argument("--details", action="store_true", help="将完整 JSON 结果直接打印到 stdout")
    parser.add_argument("--sample-limit", type=int, default=DEFAULT_SAMPLE_LIMIT, help=f"概要输出每类最多展示多少条，默认 {DEFAULT_SAMPLE_LIMIT}")
    parser.add_argument("--no-progress", action="store_true", help="关闭进度展示")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    if not args.verify_tls and requests is not None:
        try:
            requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]
        except Exception:
            pass

    rules_path = Path(args.rules).resolve()
    if not rules_path.exists():
        print(f"规则文件不存在: {rules_path}", file=sys.stderr)
        return 2
    rules = load_rules(rules_path)
    if args.retries is not None:
        rules.retry_attempts = max(0, int(args.retries))
    if args.user_agent:
        rules.user_agent = args.user_agent
    if args.verify_tls:
        rules.verify_tls = True
    elif args.insecure:
        rules.verify_tls = False
    if args.use_env_proxy:
        rules.use_env_proxy = True

    input_path = Path(args.file).resolve()
    try:
        sites = load_sites(input_path, rules)
    except ValueError as exc:
        print(f"加载输入失败: {exc}", file=sys.stderr)
        return 2
    if not sites:
        print("输入文件中没有可用站点", file=sys.stderr)
        return 2

    timeout = float(args.timeout) if args.timeout is not None else rules.default_timeout
    configured_workers = max(1, args.workers)
    effective_workers = min(configured_workers, len(sites))
    started_at = time.monotonic()
    analyses = analyze_sites(
        sites,
        timeout=timeout,
        insecure=not rules.verify_tls,
        workers=configured_workers,
        rules=rules,
        show_progress=not args.no_progress,
    )
    result = build_output(analyses, external_groups=[])
    elapsed_seconds = time.monotonic() - started_at
    result["summary"]["使用并发数"] = effective_workers
    result["summary"]["任务耗时秒"] = round(elapsed_seconds, 3)
    result["summary"]["任务耗时"] = format_duration(elapsed_seconds)

    if args.output:
        output_path = Path(args.output).resolve()
        with output_path.open("w", encoding="utf-8") as handle:
            json.dump(result, handle, ensure_ascii=False, indent=2)

    if args.details:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print_summary_report(result, sample_limit=max(1, args.sample_limit))
        if args.output:
            print()
            print(f"完整 JSON 结果已写入: {Path(args.output).resolve()}")
            print(f"规则文件: {rules_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
