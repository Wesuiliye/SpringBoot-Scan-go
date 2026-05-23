package main

import (
	"SpringBoot-Scan-go/pkg/assets"
	"SpringBoot-Scan-go/pkg/banner"
	"SpringBoot-Scan-go/pkg/check"
	"SpringBoot-Scan-go/pkg/common"
	"SpringBoot-Scan-go/pkg/scanner"
	"SpringBoot-Scan-go/pkg/vuln"
	"flag"
	"fmt"
	"os"
)

func main() {
	banner.Logo()

	urlFlag := flag.String("u", "", "对单一URL进行信息泄露扫描")
	urlFileFlag := flag.String("uf", "", "读取目标TXT进行信息泄露扫描")
	vulFlag := flag.String("v", "", "对单一URL进行漏洞利用")
	vulFileFlag := flag.String("vf", "", "读取目标TXT进行批量漏洞扫描")
	dumpFlag := flag.String("d", "", "扫描并下载SpringBoot敏感文件（可提取敏感信息）")
	dumpFileFlag := flag.String("df", "", "读取目标TXT进行批量敏感文件扫描（可提取敏感信息）")
	proxyFlag := flag.String("p", "", "使用HTTP代理")
	zoomeyeFlag := flag.String("z", "", "使用ZoomEye导出Spring框架资产")
	fofaFlag := flag.String("f", "", "使用Fofa导出Spring框架资产")
	hunterFlag := flag.String("y", "", "使用Hunter导出Spring框架资产")
	headerFlag := flag.String("t", "", "从TXT文件中导入自定义HTTP头部")

	flag.Parse()

	// Handle proxy
	proxy := ""
	if *proxyFlag != "" {
		proxyURL := fmt.Sprintf("http://%s", *proxyFlag)
		if common.CheckProxy(proxyURL) {
			proxy = proxyURL
		} else {
			os.Exit(1)
		}
	}

	// Handle custom headers
	headers := make(map[string]string)
	if *headerFlag != "" {
		fmt.Println("=====正在导入自定义HTTP头部=====")
		var err error
		headers, err = common.LoadHeadersFromFile(*headerFlag)
		if err != nil {
			fmt.Printf("[-] 导入HTTP头部失败: %s\n", err.Error())
			os.Exit(1)
		}
		fmt.Printf("[+] 已导入 %d 个HTTP头部\n", len(headers))
	}

	// Route to appropriate module
	hasAction := false

	if *urlFlag != "" {
		hasAction = true
		url := check.Check(*urlFlag, proxy, headers)
		scanner.URLScan(url, proxy, headers)
	}

	if *urlFileFlag != "" {
		hasAction = true
		scanner.BatchURLScan(*urlFileFlag, proxy, headers)
	}

	if *vulFlag != "" {
		hasAction = true
		url := check.Check(*vulFlag, proxy, headers)
		vuln.VulnScan(url, proxy, headers)
	}

	if *vulFileFlag != "" {
		hasAction = true
		vuln.PocScan(*vulFileFlag, proxy)
	}

	if *dumpFlag != "" {
		hasAction = true
		url := check.Check(*dumpFlag, proxy, headers)
		scanner.DumpScan(url, proxy, headers)
	}

	if *dumpFileFlag != "" {
		hasAction = true
		scanner.DumpFileScan(*dumpFileFlag, proxy, headers)
	}

	if *zoomeyeFlag != "" {
		hasAction = true
		assets.ZoomEyeDownload(*zoomeyeFlag, proxy)
	}

	if *fofaFlag != "" {
		hasAction = true
		assets.FofaDownload(*fofaFlag, proxy)
	}

	if *hunterFlag != "" {
		hasAction = true
		assets.HunterDownload(*hunterFlag, proxy)
	}

	if !hasAction {
		banner.Usage()
		os.Exit(1)
	}
}
