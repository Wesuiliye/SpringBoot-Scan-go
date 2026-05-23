package assets

import (
	"SpringBoot-Scan-go/pkg/common"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/fatih/color"
)

type HunterResult struct {
	Code int `json:"code"`
	Data struct {
		Arr        []struct {
			URL string `json:"url"`
		} `json:"arr"`
		RestQuota string `json:"rest_quota"`
	} `json:"data"`
}

func HunterDownload(key string, proxy string) {
	color.Green("======开始对接鹰图接口进行Spring资产测绘======")
	color.Green("[+] 您的Hunter密钥为：%s", key)

	fmt.Print("\n[.] 请输入要测绘的资产数量（默认100条）: ")
	var countStr string
	fmt.Scanln(&countStr)
	count := 100
	if countStr != "" {
		fmt.Sscanf(countStr, "%d", &count)
		if count <= 0 {
			fmt.Println("请不要输入负数")
			os.Exit(1)
		}
	}

	fmt.Print("[.] 请输入要测绘的语句（默认app.name=\"Spring Whitelabel Error\"）: ")
	var search string
	fmt.Scanln(&search)
	var searchB64 string
	if search == "" {
		searchB64 = "YXBwLm5hbWU9IlNwcmluZyBXaGl0ZWxhYmVsIEVycm9yIg=="
	} else {
		searchB64 = base64.URLEncoding.EncodeToString([]byte(search))
	}

	f, _ := os.Create("hunterout.txt")
	f.Close()

	// Test key first
	client := common.NewHTTPClient(proxy)
	testURL := fmt.Sprintf("https://hunter.qianxin.com/openApi/search?api-key=%s&search=%s&page=1&page_size=10&is_web=1",
		key, base64.URLEncoding.EncodeToString([]byte("title=\"测试\"")))

	req, err := http.NewRequest("GET", testURL, nil)
	if err != nil {
		os.Exit(1)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		common.WriteErrorLog(err.Error())
		os.Exit(1)
	}

	var testResult HunterResult
	json.NewDecoder(resp.Body).Decode(&testResult)
	resp.Body.Close()

	if testResult.Code == 200 {
		color.Red("[+] 您的key有效，测试成功！")
		if testResult.Data.RestQuota != "" {
			color.Red("[+] %s", testResult.Data.RestQuota)
		}
		time.Sleep(2 * time.Second)
	} else {
		color.Yellow("[-] API返回状态码为 %d", testResult.Code)
		color.Yellow("[-] 请根据返回的状态码，参考官方手册：https://hunter.qianxin.com/home/helpCenter?r=5-1-1")
		os.Exit(1)
	}

	// Download data
	pages := (count + 19) / 20
	for i := 1; i <= pages; i++ {
		color.Red("[+] 正在尝试下载第 %d 页数据", i)
		apiURL := fmt.Sprintf("https://hunter.qianxin.com/openApi/search?api-key=%s&search=%s&page_size=20&is_web=1&page=%d",
			key, searchB64, i)

		req, err := http.NewRequest("GET", apiURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err := client.Do(req)
		if err != nil {
			common.WriteErrorLog(err.Error())
			continue
		}

		var result HunterResult
		json.NewDecoder(resp.Body).Decode(&result)
		resp.Body.Close()

		if result.Code == 200 {
			for _, item := range result.Data.Arr {
				if item.URL != "" {
					f, _ := os.OpenFile("hunterout.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
					f.WriteString(item.URL + "\n")
					f.Close()
					fmt.Printf("Service: %s\n", item.URL)
				}
			}
			color.Red("---------------------------------------------")
			time.Sleep(2 * time.Second)
		} else {
			color.Yellow("[-] API返回状态码为 %d", result.Code)
			color.Yellow("[-] 请根据返回的状态码，参考官方手册：https://hunter.qianxin.com/home/helpCenter?r=5-1-1")
		}
	}

	lines, _ := common.ReadLines("hunterout.txt")
	if len(lines) >= 1 {
		color.Red("[+][+][+] 已经将Hunter的资产结果导出至 hunterout.txt ，共%d行记录", len(lines))
	}
}
