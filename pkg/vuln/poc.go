package vuln

import (
	"SpringBoot-Scan-go/pkg/common"
	"bufio"
	"fmt"
	"net/http"
	"os"

	"github.com/fatih/color"
)

func PocScan(filename string, proxy string) {
	f, _ := os.Create("vulout.txt")
	f.Close()

	color.Green("[+] 获取TXT名字为：%s", filename)

	_, err := os.Stat(filename)
	if err != nil {
		color.Red("未找到同目录下的TXT文件，请确保放在一个目录下")
		os.Exit(1)
	}

	color.Green("[+] 目前漏洞库内容如下：")
	for num, name := range vulnNames {
		fmt.Printf(" %d: %s\n", num, name)
	}

	fmt.Print("\n请输入要批量检测的漏洞 (例子：1,3,5 直接回车即检测全部漏洞): ")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	choicesStr := scanner.Text()

	if choicesStr == "" {
		choicesStr = "1,2,3,4,5,6,7,8,9"
	}

	choices := parseChoices(choicesStr)
	if choices == nil {
		fmt.Println("请不要输入无意义的字符串")
		os.Exit(1)
	}

	urls, err := common.ReadLines(filename)
	if err != nil {
		color.Red("[-] 读取文件失败: %s", err.Error())
		os.Exit(1)
	}

	client := common.NewHTTPClient(proxy)

	for _, rawURL := range urls {
		u := common.NormalizeURL(rawURL)

		req, err := http.NewRequest("GET", u, nil)
		if err != nil {
			color.Red("[-] URL为 %s 的目标积极拒绝请求，予以跳过！", u)
			continue
		}
		req.Header.Set("User-Agent", common.RandomUA())
		resp, err := client.Do(req)
		if err != nil {
			color.Red("[-] URL为 %s 的目标积极拒绝请求，予以跳过！", u)
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == 503 {
			continue
		}

		for _, choice := range choices {
			switch choice {
			case 1:
				JeeSpring2023(u, proxy, nil, false)
			case 2:
				CVE202222947(u, proxy, nil, false)
			case 3:
				CVE202222963(u, proxy, nil, false)
			case 4:
				CVE202222965(u, proxy, nil, false)
			case 5:
				CVE202121234(u, proxy, nil, false)
			case 6:
				SnakeYAMLRCE(u, proxy, nil, false)
			case 7:
				EurekaXstreamRCE(u, proxy, nil, false)
			case 8:
				JolokiaRCE(u, proxy, nil, false)
			case 9:
				CVE20181273(u, proxy, nil, false)
			default:
				fmt.Printf("%d 输入错误，请重新输入漏洞选择模块\n", choice)
			}
		}
	}
	color.Red("后续会加入更多漏洞利用模块，请师傅们敬请期待~")
}
