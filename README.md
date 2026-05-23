# SpringBoot-Scan-Go

SpringBoot-Scan 的 Go 语言重构版本，针对 SpringBoot 的开源渗透框架。

基于原项目 [AabyssZG/SpringBoot-Scan](https://github.com/AabyssZG/SpringBoot-Scan) Python V2.6 版本重构，使用 Go 协程实现高并发扫描，单二进制文件部署，无运行时依赖。

## 功能特性

- Spring 指纹识别（favicon MD5 + Whitelabel Error Page 特征检测）
- 敏感信息泄露端点扫描（214 个内置路径字典）
- 单 URL / 批量扫描（支持异步并发、延时控制）
- 9 个 Spring 相关高危漏洞检测与利用（含交互式 RCE）
- 批量 POC 验证
- 敏感文件扫描与下载（heapdump 等）
- 三大资产测绘平台对接（ZoomEye / Fofa / Hunter）
- HTTP 代理支持（含连通性测试）
- 自定义 HTTP 头部导入
- User-Agent 随机轮换
- TLS 自签名证书兼容

## 支持的漏洞

| # | 漏洞名称 | 类型 |
|---|---------|------|
| 1 | JeeSpring 2023 | 任意文件上传 |
| 2 | CVE-2022-22947 | Spring Cloud Gateway SpEL RCE |
| 3 | CVE-2022-22963 | Spring Cloud Function SpEL RCE |
| 4 | CVE-2022-22965 | Spring4Shell RCE |
| 5 | CVE-2021-21234 | Spring Boot 目录遍历 |
| 6 | SnakeYAML RCE | 反序列化 RCE |
| 7 | Eureka Xstream RCE | 反序列化 RCE |
| 8 | Jolokia RCE | JNDI/Logback RCE |
| 9 | CVE-2018-1273 | Spring Data Commons SpEL RCE |

## 安装

**从源码编译：**

```bash
git clone https://github.com/Wesuiliye/SpringBoot-Scan-go.git
cd SpringBoot-Scan-go
go build -o SpringBoot-Scan-go.exe .
```

要求 Go 1.21+。

## 使用方法

```
对单一URL进行信息泄露扫描:         SpringBoot-Scan-go -u http://example.com/
读取目标TXT进行批量信息泄露扫描:   SpringBoot-Scan-go -uf url.txt
对单一URL进行漏洞扫描:             SpringBoot-Scan-go -v http://example.com/
读取目标TXT进行批量漏洞扫描：      SpringBoot-Scan-go -vf url.txt
扫描并下载SpringBoot敏感文件:      SpringBoot-Scan-go -d http://example.com/
读取目标TXT进行批量敏感文件扫描:   SpringBoot-Scan-go -df url.txt
使用HTTP代理并自动进行连通性测试:    SpringBoot-Scan-go -p <代理IP:端口>
从TXT文件中导入自定义HTTP头部:       SpringBoot-Scan-go -t header.txt
通过ZoomEye密钥进行API下载数据:      SpringBoot-Scan-go -z <ZoomEye的API-KEY>
通过Fofa密钥进行API下载数据:         SpringBoot-Scan-go -f <Fofa的API-KEY>
通过Hunter密钥进行API下载数据:       SpringBoot-Scan-go -y <Hunter的API-KEY>
```

### 参数说明

| 参数 | 说明 |
|------|------|
| `-u` | 对单一 URL 进行信息泄露扫描 |
| `-uf` | 读取目标 TXT 进行批量信息泄露扫描 |
| `-v` | 对单一 URL 进行漏洞利用 |
| `-vf` | 读取目标 TXT 进行批量漏洞扫描 |
| `-d` | 扫描并下载 SpringBoot 敏感文件 |
| `-df` | 读取目标 TXT 进行批量敏感文件扫描 |
| `-p` | 使用 HTTP 代理（格式：IP:端口） |
| `-t` | 从 TXT 文件中导入自定义 HTTP 头部 |
| `-z` | 通过 ZoomEye 的 API 导出 Spring 资产 |
| `-f` | 通过 Fofa 的 API 导出 Spring 资产 |
| `-y` | 通过 Hunter 的 API 导出 Spring 资产 |

### 使用示例

**信息泄露扫描：**

```bash
SpringBoot-Scan-go -u http://example.com/
```

**漏洞利用（交互式 RCE）：**

```bash
SpringBoot-Scan-go -v http://example.com/
```

**使用代理扫描：**

```bash
SpringBoot-Scan-go -u http://example.com/ -p 127.0.0.1:8080
```

**批量漏洞扫描：**

```bash
SpringBoot-Scan-go -vf url.txt
```

**通过 Fofa 获取资产并批量扫描：**

```bash
SpringBoot-Scan-go -f <Fofa_API_KEY>
SpringBoot-Scan-go -uf fofaout.txt
```

## 输出文件

| 文件 | 说明 |
|------|------|
| `urlout.txt` | 单 URL 信息泄露扫描结果 |
| `output.txt` | 批量信息泄露扫描结果 |
| `vulout.txt` | 批量漏洞扫描结果 |
| `dumpout.txt` | 敏感文件扫描结果 |
| `zoomout.txt` | ZoomEye 资产导出结果 |
| `fofaout.txt` | Fofa 资产导出结果 |
| `hunterout.txt` | Hunter 资产导出结果 |
| `error.log` | 错误日志 |

## 项目结构

```
SpringBoot-Scan-go/
├── main.go                     # 入口，CLI参数解析
├── go.mod                      # Go模块定义
└── pkg/
    ├── banner/banner.go        # Logo和帮助信息
    ├── common/common.go        # 公共工具（HTTP客户端、代理、字典等）
    ├── check/check.go          # Spring指纹识别
    ├── scanner/
    │   ├── scanner.go          # 端点扫描（单URL / 批量异步并发）
    │   └── dump.go             # 敏感文件扫描与下载
    ├── vuln/
    │   ├── vuln.go             # 漏洞利用模块（9个CVE，含交互式RCE）
    │   └── poc.go              # 批量POC验证
    └── assets/
        ├── zoomeye.go          # ZoomEye API资产收集
        ├── fofa.go             # Fofa API资产收集
        └── hunter.go           # Hunter API资产收集
```

## 与原版对比

| 特性 | Python 版 | Go 版 |
|------|-----------|-------|
| 运行时依赖 | Python 3.10+、pip 包 | 单二进制，零依赖 |
| 并发模型 | asyncio + aiohttp | goroutine + sync |
| 部署方式 | 需安装 Python 环境 | 单文件直接运行 |
| 扫描速度 | 多进程 | 协程并发 |

## 原项目

本工具基于 [AabyssZG/SpringBoot-Scan](https://github.com/AabyssZG/SpringBoot-Scan) 用 Go 语言重构。

- 原作者：曾哥 (@AabyssZG)
- 多进程速度提升：Fkalis
- GUI 版本：[@13exp](https://github.com/13exp/SpringBoot-Scan-GUI)

## 免责声明

本工具仅用于安全测试和学习目的。使用前请确保您已获得目标系统的授权。

1. 如果您下载、安装、使用、修改本工具及相关代码，即表明您信任本工具
2. 在使用本工具时造成对您自己或他人任何形式的损失和伤害，我们不承担任何责任
3. 如您在使用本工具的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任
4. 请您务必审慎阅读、充分理解各条款内容，特别是免除或者限制责任的条款，并选择接受或不接受
5. 除非您已阅读并接受本协议所有条款，否则您无权下载、安装或使用本工具
6. 您的下载、安装、使用等行为即视为您已阅读并同意上述协议的约束

## License

MIT
