package assets

import (
	"SpringBoot-Scan-go/pkg/common"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/fatih/color"
)

type FofaResult struct {
	Error    bool       `json:"error"`
	ErrMsg   string     `json:"errmsg"`
	Results  [][]string `json:"results"`
}

type FofaInfo struct {
	Error    bool   `json:"error"`
	Username string `json:"username"`
	IsVIP    bool   `json:"isvip"`
	ErrMsg   string `json:"errmsg"`
}

func FofaDownload(key string, proxy string) {
	color.Green("======开始对接Fofa接口进行Spring资产测绘======")
	color.Green("[+] 您的Fofa密钥为：%s", key)

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

	fmt.Print("[.] 请输入要测绘的语句（默认icon_hash=\"116323821\"||body=\"Whitelabel Error Page\"）: ")
	var search string
	fmt.Scanln(&search)
	var searchB64 string
	if search == "" {
		searchB64 = "aWNvbl9oYXNoPSIxMTYzMjM4MjEifHxib2R5PSJXaGl0ZWxhYmVsIEVycm9yIFBhZ2Ui"
	} else {
		searchB64 = base64.StdEncoding.EncodeToString([]byte(search))
	}

	f, _ := os.Create("fofaout.txt")
	f.Close()

	// Test key first
	client := common.NewHTTPClient(proxy)
	infoURL := fmt.Sprintf("https://fofa.info/api/v1/info/my?key=%s", key)
	req, err := http.NewRequest("GET", infoURL, nil)
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
	var info FofaInfo
	json.NewDecoder(resp.Body).Decode(&info)
	resp.Body.Close()

	if info.Error {
		color.Yellow("[-] 发生错误，API返回结果为 %s", info.ErrMsg)
		color.Yellow("[-] 请根据返回的结果，参考官方手册：https://fofa.info/api")
		os.Exit(1)
	}
	color.Red("[+] 您的key有效，测试成功！您的账号为 %s", info.Username)
	if info.IsVIP {
		color.Red("[+] 您的账号为VIP会员")
	} else {
		color.Yellow("[.] 您的账号不是VIP会员")
	}

	// Download data
	pages := (count + 99) / 100
	for i := 1; i <= pages; i++ {
		color.Red("[+] 正在尝试下载第 %d 页数据", i)
		apiURL := fmt.Sprintf("https://fofa.info/api/v1/search/all?&key=%s&qbase64=%s&page=%d", key, searchB64, i)

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

		var result FofaResult
		json.NewDecoder(resp.Body).Decode(&result)
		resp.Body.Close()

		if !result.Error {
			for _, service := range result.Results {
				if len(service) > 0 {
					outURL := service[0]
					if !strings.Contains(outURL, "https") {
						outURL = "http://" + outURL
					}
					f, _ := os.OpenFile("fofaout.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
					f.WriteString(outURL + "\n")
					f.Close()
					fmt.Printf("Service: %s\n", outURL)
				}
			}
			color.Red("---------------------------------------------")
		} else {
			color.Yellow("[-] API返回状态码为 %d", resp.StatusCode)
			color.Yellow("[-] 请根据返回的状态码，参考官方手册：https://fofa.info/api")
		}
	}

	lines, _ := common.ReadLines("fofaout.txt")
	if len(lines) >= 1 {
		color.Red("[+][+][+] 已经将Fofa的资产结果导出至 fofaout.txt ，共%d行记录", len(lines))
	}
}
