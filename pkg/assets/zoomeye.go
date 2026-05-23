package assets

import (
	"SpringBoot-Scan-go/pkg/common"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/fatih/color"
)

type ZoomEyeResult struct {
	Matches []struct {
		PortInfo struct {
			Hostname  string `json:"hostname"`
			Service   string `json:"service"`
			Port      int    `json:"port"`
		} `json:"portinfo"`
		IP string `json:"ip"`
	} `json:"matches"`
}

func ZoomEyeDownload(key string, proxy string) {
	color.Green("======开始对接ZoomEye接口进行Spring资产测绘======")
	color.Green("[+] 您的ZoomEye密钥为：%s", key)

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

	fmt.Print("[.] 请输入要测绘的语句（默认app:\"Spring Framework\"）: ")
	var search string
	fmt.Scanln(&search)
	if search == "" {
		search = `app:"Spring Framework"`
	}

	f, _ := os.Create("zoomout.txt")
	f.Close()

	pages := (count + 19) / 20
	client := common.NewHTTPClient(proxy)

	for i := 1; i <= pages; i++ {
		color.Red("[+] 正在尝试下载第 %d 页数据", i)
		apiURL := fmt.Sprintf("https://api.zoomeye.org/host/search?query=%s&t=web&page=%d", search, i)

		req, err := http.NewRequest("GET", apiURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("API-KEY", key)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err := client.Do(req)
		if err != nil {
			common.WriteErrorLog(err.Error())
			continue
		}

		if resp.StatusCode == 200 || resp.StatusCode == 201 {
			var result ZoomEyeResult
			json.NewDecoder(resp.Body).Decode(&result)
			resp.Body.Close()

			if len(result.Matches) == 0 {
				color.Yellow("[-] 没有搜索到任何资产，请确认你的语法是否正确")
				break
			}

			for _, match := range result.Matches {
				scheme := "http://"
				if strings.Contains(match.PortInfo.Service, "https") {
					scheme = "https://"
				}
				var outURL string
				if match.PortInfo.Hostname != "" {
					outURL = fmt.Sprintf("%s%s:%d", scheme, match.PortInfo.Hostname, match.PortInfo.Port)
				} else {
					outURL = fmt.Sprintf("%s%s:%d", scheme, match.IP, match.PortInfo.Port)
				}
				f, _ := os.OpenFile("zoomout.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
				f.WriteString(outURL + "\n")
				f.Close()
				fmt.Printf("Service: %s\n", outURL)
			}
			color.Red("---------------------------------------------")
		} else {
			color.Yellow("[-] API返回状态码为 %d", resp.StatusCode)
			color.Yellow("[-] 请根据返回的状态码，参考官方手册：https://www.zoomeye.org/doc")
			resp.Body.Close()
		}
	}

	lines, _ := common.ReadLines("zoomout.txt")
	if len(lines) >= 1 {
		color.Red("[+][+][+] 已经将ZoomEye的资产结果导出至 zoomout.txt ，共%d行记录", len(lines))
	}
}
