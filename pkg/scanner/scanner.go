package scanner

import (
	"SpringBoot-Scan-go/pkg/common"
	"crypto/md5"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
)

func URLScan(baseURL string, proxy string, headers map[string]string) {
	f, _ := os.Create("urlout.txt")
	f.Close()

	color.Cyan("======开始对目标URL测试SpringBoot信息泄露端点======")
	fmt.Print("\n是否要延时扫描 (默认0秒): ")
	var sleepStr string
	fmt.Scanln(&sleepStr)
	sleepSec := 0
	if sleepStr != "" {
		fmt.Sscanf(sleepStr, "%d", &sleepSec)
	}

	dict := common.ReadDirDict()
	encountered := make(map[string]bool)
	client := common.NewHTTPClient(proxy)

	for _, path := range dict {
		u := baseURL + path
		req, err := http.NewRequest("GET", u, nil)
		if err != nil {
			continue
		}
		mergedHeaders := common.MergeHeaders(map[string]string{"User-Agent": common.RandomUA()}, headers)
		for k, v := range mergedHeaders {
			req.Header.Set(k, v)
		}

		resp, err := client.Do(req)
		if err != nil {
			color.Red("[-] URL为 " + u + " 的目标积极拒绝请求，予以跳过！")
			fmt.Println(err)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		bodyStr := string(body)

		if sleepSec > 0 {
			time.Sleep(time.Duration(sleepSec) * time.Second)
		}

		if resp.StatusCode == 503 {
			os.Exit(1)
		}

		if resp.StatusCode == 200 &&
			!strings.Contains(bodyStr, "need login") &&
			!strings.Contains(bodyStr, "禁止访问") &&
			len(body) != 3318 &&
			!strings.Contains(bodyStr, "无访问权限") &&
			!strings.Contains(bodyStr, "认证失败") {
			h := md5.Sum(body)
			contentHash := fmt.Sprintf("%x", h)
			if !encountered[contentHash] {
				encountered[contentHash] = true
				color.Red("[+] 状态码%d 信息泄露URL为:%s    页面长度为:%d", resp.StatusCode, u, len(body))
				f, _ := os.OpenFile("urlout.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
				f.WriteString(u + "\n")
				f.Close()
			} else {
				color.Magenta("[*] 已存在重复内容的URL:" + u)
			}
		} else if resp.StatusCode == 200 {
			color.Red("[+] 状态码%d 但无法获取信息 URL为:%s    页面长度为:%d", resp.StatusCode, u, len(body))
		} else {
			color.Yellow("[-] 状态码%d 无法访问URL为:%s", resp.StatusCode, u)
		}
	}

	lines, _ := common.ReadLines("urlout.txt")
	count := len(lines)
	if count >= 1 {
		fmt.Println()
		color.Red("[+][+][+] 发现目标URL存在SpringBoot敏感信息泄露，已经导出至 urlout.txt ，共%d行记录", count)
	} else {
		fmt.Println()
		color.Yellow("[-] 目标URL没有存在SpringBoot敏感信息泄露")
	}
}

func BatchURLScan(urlFile string, proxy string, headers map[string]string) {
	f, _ := os.Create("output.txt")
	f.Close()

	color.Cyan("======开始读取目标TXT并测试SpringBoot信息泄露端点======")
	start := time.Now()

	fmt.Print("\n是否要延时扫描 (默认不延时，必须是整数): ")
	var sleepStr string
	fmt.Scanln(&sleepStr)
	sleepSec := 0
	if sleepStr != "" {
		fmt.Sscanf(sleepStr, "%d", &sleepSec)
	}

	fmt.Print("请输入最大并发数 (默认10): ")
	var maxConcStr string
	fmt.Scanln(&maxConcStr)
	maxConcurrency := 10
	if maxConcStr != "" {
		fmt.Sscanf(maxConcStr, "%d", &maxConcurrency)
	}

	urls, err := common.ReadLines(urlFile)
	if err != nil {
		color.Red("[-] 读取URL文件失败: %s", err.Error())
		os.Exit(1)
	}

	var mu sync.Mutex
	sem := make(chan struct{}, maxConcurrency)
	var wg sync.WaitGroup

	for _, rawURL := range urls {
		targetURL := common.NormalizeURL(rawURL)
		dict := common.ReadDirDict()

		for _, path := range dict {
			wg.Add(1)
			sem <- struct{}{}
			go func(u, p string) {
				defer wg.Done()
				defer func() { <-sem }()
				fullURL := u + p
				asyncScan(fullURL, proxy, headers, &mu, sleepSec)
			}(targetURL, path)
		}
	}

	wg.Wait()

	lines, _ := common.ReadLines("output.txt")
	count := len(lines)
	if count >= 1 {
		fmt.Println()
		color.Red("[+][+][+] 发现目标TXT内存在SpringBoot敏感信息泄露，已经导出至 output.txt ，共%d行记录", count)
	} else {
		fmt.Println()
		color.Yellow("[-] 目标TXT内没有存在SpringBoot敏感信息泄露")
	}
	elapsed := time.Since(start)
	color.Red("[+] 批量扫描共耗时 %.2f 秒", elapsed.Seconds())
}

func asyncScan(u string, proxy string, headers map[string]string, mu *sync.Mutex, sleepSec int) {
	client := common.NewHTTPClient(proxy)
	mergedHeaders := common.MergeHeaders(map[string]string{"User-Agent": common.RandomUA()}, headers)

	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return
	}
	for k, v := range mergedHeaders {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	bodyStr := string(body)

	if sleepSec > 0 {
		time.Sleep(time.Duration(sleepSec) * time.Second)
	}

	if resp.StatusCode == 200 &&
		!strings.Contains(bodyStr, "need login") &&
		!strings.Contains(bodyStr, "禁止访问") &&
		len(body) != 3318 &&
		!strings.Contains(bodyStr, "无访问权限") &&
		!strings.Contains(bodyStr, "认证失败") {

		// Verify by comparing with garbage URL length
		garbageURL := u + "QWEASD123"
		req2, err := http.NewRequest("GET", garbageURL, nil)
		if err == nil {
			for k, v := range mergedHeaders {
				req2.Header.Set(k, v)
			}
			resp2, err := client.Do(req2)
			if err == nil {
				body2, _ := io.ReadAll(resp2.Body)
				resp2.Body.Close()
				if len(body) != len(body2) {
					mu.Lock()
					color.Red("[+] 状态码%d 信息泄露URL为:%s    页面长度为:%d", resp.StatusCode, u, len(body))
					f, _ := os.OpenFile("output.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
					f.WriteString(u + "\n")
					f.Close()
					mu.Unlock()
				} else {
					color.Magenta("[-] 发现重复长度URL为: %s    页面长度为:%d", u, len(body))
				}
			}
		}
	} else if resp.StatusCode == 200 {
		color.Red("[+] 状态码%d 但无法获取信息 URL为:%s    页面长度为:%d", resp.StatusCode, u, len(body))
	} else {
		color.Yellow("[-] 状态码%d 无法访问URL为:%s", resp.StatusCode, u)
	}
}
