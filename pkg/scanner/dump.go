package scanner

import (
	"SpringBoot-Scan-go/pkg/common"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
)

var dumpPaths = []string{
	"actuator/heapdump",
	"heapdump",
	"heapdump.json",
	"gateway/actuator/heapdump",
	"hystrix.stream",
	"artemis-portal/artemis/heapdump",
}

func DumpScan(baseURL string, proxy string, headers map[string]string) {
	color.Cyan("======开始对目标URL测试SpringBoot敏感文件泄露并下载======")
	client := common.NewHTTPClient(proxy)
	mergedHeaders := common.MergeHeaders(map[string]string{"User-Agent": common.RandomUA()}, headers)

	for _, path := range dumpPaths {
		fullURL := baseURL + path
		req, err := http.NewRequest("HEAD", fullURL, nil)
		if err != nil {
			continue
		}
		for k, v := range mergedHeaders {
			req.Header.Set(k, v)
		}

		resp, err := client.Do(req)
		if err != nil {
			color.Yellow("[-] 在 /%s 未发现敏感文件泄露", path)
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == 200 {
			color.Red("[+][+][+] 发现 /%s 敏感文件泄露 下载端点URL为:%s", path, fullURL)
			downloadFile(fullURL, path, proxy, mergedHeaders)
			return
		} else {
			color.Yellow("[-] 在 /%s 未发现敏感文件泄露", path)
		}
	}
}

func downloadFile(url string, filename string, proxy string, headers map[string]string) {
	client := common.NewHTTPClient(proxy)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Printf("[-] 下载失败: %s\n", err.Error())
		return
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("[-] 下载失败: %s\n", err.Error())
		common.WriteErrorLog(err.Error())
		return
	}
	defer resp.Body.Close()

	total := resp.ContentLength
	outFile, err := os.Create(filename)
	if err != nil {
		fmt.Printf("[-] 创建文件失败: %s\n", err.Error())
		return
	}
	defer outFile.Close()

	var downloaded int64
	buf := make([]byte, 32*1024)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			written, _ := outFile.Write(buf[:n])
			downloaded += int64(written)
			if total > 0 {
				percent := float64(downloaded) / float64(total) * 100
				fmt.Printf("\r[%s] %.2f%% (%d/%d bytes)",
					filename, percent, downloaded, total)
			} else {
				fmt.Printf("\r[%s] %d bytes downloaded", filename, downloaded)
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
	}
	fmt.Println()
}

func DumpFileScan(inputFile string, proxy string, headers map[string]string) {
	client := common.NewHTTPClient(proxy)
	mergedHeaders := common.MergeHeaders(map[string]string{"User-Agent": common.RandomUA()}, headers)

	urls, err := common.ReadLines(inputFile)
	if err != nil {
		color.Red("[-] 读取URL文件失败: %s", err.Error())
		os.Exit(1)
	}

	color.Cyan("======开始读取目标TXT并扫描SpringBoot信息文件端点======")
	fmt.Print("\n是否要延时扫描 (默认0秒): ")
	var sleepStr string
	fmt.Scanln(&sleepStr)
	sleepSec := 0
	if sleepStr != "" {
		fmt.Sscanf(sleepStr, "%d", &sleepSec)
	}

	var validURLs []string

	for _, rawURL := range urls {
		targetURL := common.NormalizeURL(rawURL)
		for _, path := range dumpPaths {
			fullURL := strings.TrimRight(targetURL, "/") + "/" + strings.TrimLeft(path, "/")
			fullURL = strings.ReplaceAll(fullURL, "\n", "")

			req, err := http.NewRequest("HEAD", fullURL, nil)
			if err != nil {
				continue
			}
			for k, v := range mergedHeaders {
				req.Header.Set(k, v)
			}
			req.Header.Set("User-Agent", common.RandomUA())

			resp, err := client.Do(req)
			if err != nil {
				fmt.Printf("[-] 访问 %s 出现错误\n", fullURL)
				common.WriteErrorLog(err.Error())
				continue
			}
			resp.Body.Close()

			if sleepSec > 0 {
				time.Sleep(time.Duration(sleepSec) * time.Second)
			}

			if resp.StatusCode == 200 {
				color.Red("[+] 发现SpringBoot敏感文件泄露，地址为 %s", fullURL)
				validURLs = append(validURLs, fullURL)
			} else {
				color.Yellow("[-] 没有发现SpringBoot敏感文件泄露，地址 %s 状态码为 %d", fullURL, resp.StatusCode)
			}
		}
	}

	outFile, _ := os.Create("dumpout.txt")
	for _, u := range validURLs {
		outFile.WriteString(u + "\n")
	}
	outFile.Close()

	if len(validURLs) >= 1 {
		fmt.Println()
		color.Red("[+][+][+] 发现目标TXT内存在SpringBoot敏感文件泄露，已经导出至 dumpout.txt ，共%d行记录", len(validURLs))
	} else {
		color.Yellow("[-] 读取指定TXT没有存在SpringBoot敏感文件泄露")
	}
}
