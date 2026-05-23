package check

import (
	"SpringBoot-Scan-go/pkg/common"
	"crypto/md5"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/fatih/color"
)

const SpringFaviconHash = "0488faca4c19046b94d07c3ee83cf9d6"

func springCheck(baseURL string, proxy string, headers map[string]string) {
	color.Cyan("[.] 正在进行Spring的指纹识别")
	paths := []string{"favicon.ico", "AabyssZG666"}
	checkStatus := 0

	client := common.NewHTTPClient(proxy)
	for _, path := range paths {
		testURL := baseURL + path
		req, err := http.NewRequest("GET", testURL, nil)
		if err != nil {
			continue
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		req.Header.Set("User-Agent", common.RandomUA())

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		bodyStr := string(body)

		contentType := resp.Header.Get("Content-Type")

		if bodyStr != "" && contains(bodyStr, "timestamp") {
			color.Red("[+] 站点报错内容符合Spring特征，识别成功")
			checkStatus = 1
		} else if contains(contentType, "image") || contains(contentType, "octet-stream") {
			h := md5.Sum(body)
			faviconHash := fmt.Sprintf("%x", h)
			if faviconHash == SpringFaviconHash {
				color.Red("[+] 站点Favicon是Spring图标，识别成功")
				checkStatus = 1
			}
		}
		if checkStatus == 0 {
			color.Yellow("[-] 站点指纹不符合Spring特征，可能不是Spring框架")
			checkStatus = 2
		}
	}
}

func Check(rawURL string, proxy string, headers map[string]string) string {
	url := common.NormalizeURL(rawURL)

	client := common.NewHTTPClient(proxy)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		color.Red("[-] URL为 " + url + " 的目标积极拒绝请求，予以跳过！")
		common.WriteErrorLog(err.Error())
		os.Exit(1)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("User-Agent", common.RandomUA())

	resp, err := client.Do(req)
	if err != nil {
		color.Red("[-] URL为 " + url + " 的目标积极拒绝请求，予以跳过！")
		common.WriteErrorLog(err.Error())
		os.Exit(1)
	}
	resp.Body.Close()

	if resp.StatusCode == 503 || resp.StatusCode == 502 {
		color.Red("[-] 网页状态码为503或502")
		os.Exit(1)
	}

	springCheck(url, proxy, headers)
	return url
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsInner(s, substr))
}

func containsInner(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
