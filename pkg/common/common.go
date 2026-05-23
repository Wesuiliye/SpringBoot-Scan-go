package common

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
)

var UserAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36,Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.93 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36,Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/30.0.1599.17 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36,Mozilla/5.0 (X11; NetBSD) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.116 Safari/537.36",
	"Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML like Gecko) Chrome/44.0.2403.155 Safari/537.36",
	"Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27",
	"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:23.0) Gecko/20130406 Firefox/23.0",
	"Opera/9.80 (Windows NT 5.1; U; zh-sg) Presto/2.9.181 Version/12.00",
}

var OutTime = 10 * time.Second

func RandomUA() string {
	return UserAgents[rand.Intn(len(UserAgents))]
}

func NewHTTPClient(proxyURL string) *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	if proxyURL != "" {
		proxy, err := url.Parse(proxyURL)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxy)
		}
	}
	return &http.Client{
		Transport: transport,
		Timeout:   OutTime,
	}
}

func MergeHeaders(h1, h2 map[string]string) map[string]string {
	merged := make(map[string]string)
	for k, v := range h1 {
		merged[k] = v
	}
	for k, v := range h2 {
		merged[k] = v
	}
	return merged
}

func NormalizeURL(rawURL string) string {
	if !strings.Contains(rawURL, "://") {
		rawURL = "http://" + rawURL
	}
	if !strings.HasSuffix(rawURL, "/") {
		rawURL += "/"
	}
	return rawURL
}

func ReadLines(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

func LoadHeadersFromFile(filename string) (map[string]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	headers := make(map[string]string)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return headers, scanner.Err()
}

func CheckProxy(proxyURL string) bool {
	color.Cyan("=====检测代理可用性中=====")
	client := NewHTTPClient(proxyURL)
	testURL := "https://www.baidu.com/"
	req, err := http.NewRequest("GET", testURL, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := client.Do(req)
	if err != nil {
		color.Magenta("[-] 代理不可用，请更换代理！")
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		fmt.Printf("GET www.baidu.com 状态码为:%d\n", resp.StatusCode)
		color.Cyan("[+] 代理可用，马上执行！")
		return true
	}
	return false
}

func WriteErrorLog(msg string) {
	f, err := os.OpenFile("error.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	f.WriteString(msg + "\n")
}

func ReadDirDict() []string {
	// Embedded dictionary
	dict := []string{
		"api-docs", "actuator", "actuator/./env", "actuator/auditLog", "actuator/auditevents",
		"actuator/autoconfig", "actuator/beans", "actuator/caches", "actuator/conditions",
		"actuator/configurationMetadata", "actuator/configprops", "actuator/dump", "actuator/env",
		"actuator/events", "actuator/exportRegisteredServices", "actuator/features", "actuator/flyway",
		"actuator/health", "actuator/healthcheck", "actuator/httptrace", "actuator/hystrix.stream",
		"actuator/info", "actuator/integrationgraph", "actuator/jolokia", "actuator/logfile",
		"actuator/loggers", "actuator/loggingConfig", "actuator/liquibase", "actuator/metrics",
		"actuator/mappings", "actuator/scheduledtasks", "actuator/swagger-ui.html", "actuator/prometheus",
		"actuator/refresh", "actuator/registeredServices", "actuator/releaseAttributes",
		"actuator/resolveAttributes", "actuator/scheduledtasks", "actuator/sessions",
		"actuator/springWebflow", "actuator/sso", "actuator/ssoSessions", "actuator/statistics",
		"actuator/status", "actuator/threaddump", "actuator/trace", "actuator/env.css",
		"artemis-portal/artemis/env", "artemis/api", "artemis/api/env", "auditevents", "autoconfig",
		"api", "api.html", "api/actuator", "api/doc", "api/index.html", "api/swaggerui",
		"api/swagger-ui.html", "api/swagger", "api/swagger/ui", "api/v2/api-docs",
		"api/v2;%0A/api-docs", "api/v2;%252Ftest/api-docs", "api-docs", "beans", "caches",
		"cloudfoundryapplication", "conditions", "configprops", "distv2/index.html", "docs",
		"doc.html", "druid", "druid/index.html", "druid/login.html", "druid/websession.html",
		"dubbo-provider/distv2/index.html", "dump", "decision/login", "entity/all", "env",
		"env.css", "env/(name)", "eureka", "flyway", "functionRouter", "gateway/actuator",
		"gateway/actuator/auditevents", "gateway/actuator/beans", "gateway/actuator/conditions",
		"gateway/actuator/configprops", "gateway/actuator/env", "gateway/actuator/health",
		"gateway/actuator/httptrace", "gateway/actuator/hystrix.stream", "gateway/actuator/info",
		"gateway/actuator/jolokia", "gateway/actuator/logfile", "gateway/actuator/loggers",
		"gateway/actuator/mappings", "gateway/actuator/metrics", "gateway/actuator/scheduledtasks",
		"gateway/actuator/swagger-ui.html", "gateway/actuator/threaddump", "gateway/actuator/trace",
		"gateway/routes", "health", "httptrace", "hystrix", "info", "integrationgraph", "jolokia",
		"jolokia/list", "jeecg/swagger-ui", "jeecg/swagger/", "libs/swaggerui", "liquibase",
		"logfile", "loggers", "liquibase", "metrics", "mappings", "monitor", "nacos",
		"prod-api/actuator", "prometheus", "portal/conf/config.properties", "portal/env/", "refresh",
		"scheduledtasks", "sessions", "spring-security-oauth-resource/swagger-ui.html",
		"spring-security-rest/api/swagger-ui.html", "static/swagger.json", "sw/swagger-ui.html",
		"swagger", "swagger/codes", "swagger/doc.json", "swagger/index.html",
		"swagger/static/index.html", "swagger/swagger-ui.html", "Swagger/ui/index", "swagger/ui",
		"swagger/v1/swagger.json", "swagger/v2/swagger.json", "swagger-dubbo/api-docs",
		"swagger-resources", "swagger-resources/configuration/ui",
		"swagger-resources/configuration/security", "swagger-ui", "swagger-ui.html",
		"swagger-ui.html;", "swagger-ui/html", "swagger-ui/index.html", "system/druid/index.html",
		"system/druid/webseesion.html", "threaddump", "template/swagger-ui.html", "trace", "users",
		"user/swagger-ui.html", "version", "v1/api-docs/", "v2/api-docs/", "v3/api-docs/",
		"v1/swagger-resources", "v2/swagger-resources", "v3/swagger-resources",
		"v1.1/swagger-ui.html", "v1.1;%0A/api-docs", "v1.2/swagger-ui.html", "v1.2;%0A/api-docs",
		"v1.3/swagger-ui.html", "v1.3;%0A/api-docs", "v1.4/swagger-ui.html", "v1.4;%0A/api-docs",
		"v1.5/swagger-ui.html", "v1.5;%0A/api-docs", "v1.6/swagger-ui.html", "v1.6;%0A/api-docs",
		"v1.7/swagger-ui.html", "v1.7;%0A/api-docs", "v1.8/swagger-ui.html", "v1.8;%0A/api-docs",
		"v1.9/swagger-ui.html", "v1.9;%0A/api-docs", "v2.0/swagger-ui.html", "v2.0;%0A/api-docs",
		"v2.1/swagger-ui.html", "v2.1;%0A/api-docs", "v2.2/swagger-ui.html", "v2.2;%0A/api-docs",
		"v2.3/swagger-ui.html", "v2.3;%0A/api-docs", "v1/swagger.json", "v2/swagger.json",
		"v3/swagger.json", "v2;%0A/api-docs", "v3;%0A/api-docs", "v2;%252Ftest/api-docs",
		"v3;%252Ftest/api-docs", "webpage/system/druid/websession.html",
		"webpage/system/druid/index.html", "webroot/decision/login",
		"webjars/springfox-swagger-ui/swagger-ui-standalone-preset.js",
		"webjars/springfox-swagger-ui/swagger-ui-standalone-preset.js?v=2.9.2",
		"webjars/springfox-swagger-ui/springfox.js",
		"webjars/springfox-swagger-ui/springfox.js?v=2.9.2",
		"webjars/springfox-swagger-ui/swagger-ui-bundle.js",
		"webjars/springfox-swagger-ui/swagger-ui-bundle.js?v=2.9.2",
		"%20/swagger-ui.html",
	}
	return dict
}

func ReadBody(resp *http.Response) string {
	if resp == nil {
		return ""
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}
	return string(body)
}
