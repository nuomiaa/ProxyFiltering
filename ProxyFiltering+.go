package main

import (
	"fmt"
	"github/socks"
	"io/ioutil"
	"myloc"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	lip string
	mu sync.Mutex
	clear  map[string]func()
	ipList []string
	errorIP int
	repeatIP int
	anonymousIP int
	transparentIP int
	apiURL = "http://icanhazip.com"
)

func init() {
	clear = make(map[string]func()) // 初始化
	clear["linux"] = func() {
		cmd := exec.Command("clear") // Linux
		cmd.Stdout = os.Stdout
		cmd.Run()
	}
	clear["windows"] = func() {
		cmd := exec.Command("cmd", "/c", "cls") //Windows
		cmd.Stdout = os.Stdout
		cmd.Run()
	}
}

func callClear() {
	value, ok := clear[runtime.GOOS]
	if ok { value() }
}

func localIP() string {
	client := http.Client{ Timeout: 120 * time.Second }
	res,err := client.Get("http://icanhazip.com")
	if err != nil { return "" }
	defer res.Body.Close()
	temp, _ := ioutil.ReadAll(res.Body)
	if res.StatusCode!=http.StatusOK && string(temp)!="" { return "" }
	return string(temp)
}

func proxyFiltering(addr string, timeout int, agreement string, wg *sync.WaitGroup) {
	proxyUrl,_ := url.Parse(agreement+"://"+addr)
	tr := &http.Transport{}
	if agreement=="http" || agreement=="https" {
		tr = &http.Transport{
			Proxy: http.ProxyURL(proxyUrl),
		}
	} else {
		tr = &http.Transport{
			Dial: socks.Dial(agreement + "://" + addr + "?timeout=" + strconv.Itoa(timeout) + "s"),
		}
	}

	client := http.Client{
		Timeout: time.Duration(timeout) * time.Second,
		Transport: tr,
	}
	res,err := client.Get(apiURL)
	if err != nil {
		mu.Lock()
		errorIP++
		defer mu.Unlock()
		wg.Done()
		//fmt.Println("失效 -> "+addr)
		return
	}

	defer res.Body.Close()
	temp, _ := ioutil.ReadAll(res.Body)
	if res.StatusCode!=http.StatusOK || string(temp)=="" {
		mu.Lock()
		errorIP++
		//fmt.Println("失效 -> "+addr)
		defer mu.Unlock()
		wg.Done()
		return
	}

	b, err := regexp.MatchString("((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})(\\.((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})){3}", string(temp))
	if !b || err != nil {
		mu.Lock()
		errorIP++
		//fmt.Println("失效 -> "+addr)
		defer mu.Unlock()
		wg.Done()
		return
	}

	h := strings.Split(addr, ":")
	detail := myloc.IPLoc.Find(h[0])
	info := " - " + detail.String()
	//fmt.Println(detail.Country, detail.Province, detail.City, detail.County)
	/*
	if ipLibrary {
		q := qqwry.NewQQwry("qqwry.dat")
		h := strings.Split(addr, ":")
		q.Find(h[0])
		info = " - " + q.Country + " - " + q.City
	}
	*/

	if string(temp) == lip {
		mu.Lock()
		transparentIP++
		defer mu.Unlock()
		msgWarning("『PF』透明 -> " + addr + info)
	} else {
		mu.Lock()
		anonymousIP++
		defer mu.Unlock()
		ipList = append(ipList, addr)
		msgSuccess("『PF』匿名 -> " + addr + info)
	}
	wg.Done()
}

func readFile(file string) (list []string, err error) {
	res,err := ioutil.ReadFile(file)
	return strings.Split(strings.Replace(string(res), "\r\n", "\n", -1), "\n"), err
}

func writeFile(file string, data []byte) (err error) {
	return ioutil.WriteFile(file, data, 0755)
}

func SliceRemoveDuplicates(slice []string) []string {
	sort.Strings(slice)
	i := 0
	var j int
	for {
		if i >= len(slice)-1 { break }
		for j = i + 1; j < len(slice) && slice[i] == slice[j]; j++ {
			repeatIP++
		}
		slice = append(slice[:i+1], slice[j:]...)
		i++
	}

	return slice
}

func fileExist(path string) bool {
	_, err := os.Lstat(path)
	return !os.IsNotExist(err)
}

func msg(msg string) {
	fmt.Printf("\033[1;37m%s\033[0m\n", msg)
}
func msgError(msg string) {
	fmt.Printf("\033[1;31m%s\033[0m\n", msg)
}
func msgWarning(msg string) {
	fmt.Printf("\033[1;33m%s\033[0m\n", msg)
}
func msgSuccess(msg string) {
	fmt.Printf("\033[1;32m%s\033[0m\n", msg)
}
func msgBlack(msg string) {
	fmt.Printf("\033[1;30m%s\033[0m\n", msg)
}
func msgBlue(msg string) {
	fmt.Printf("\033[1;36m%s\033[0m\n", msg)
}
func msgViolet(msg string) {
	fmt.Printf("\033[1;35m%s\033[0m\n", msg)
}

func main() {
	callClear()
	msgBlue("『ProxyFiltering+』1.8")
	msgViolet("TG: @DDoS_DataStation\n")

	// 检查命令格式
	if len(os.Args) < 6 || len(os.Args) > 7 {
		msgError("『PF』错误：命令格式不正确！")
		msgWarning("『PF』协议：http、https、socks4、socks5")
		msgWarning("『PF』示例：./pf http 15 1000 origin.txt proxy.txt")
		msgWarning("『PF』格式：./pf 检测协议 超时(秒) 协程 输入 输出 [可选:检测地址(返回请求IP)]")
		return
	}

	if len(os.Args) == 7 {
		apiURL = os.Args[6]
	}

	var err error
	var list_ []string
	agreement := os.Args[1]
	timeout,_ := strconv.Atoi(os.Args[2])
	thread, _ := strconv.Atoi(os.Args[3])
	inputFile := os.Args[4]
	outputFile := os.Args[5]
	if agreement!="http" && agreement!="https" && agreement!="socks4" && agreement!="socks5" {
		msgError("『PF』错误：不支持 [ "+agreement+" ] 协议")
		return
	}
	if timeout < 1 {
		msgError("『PF』错误：超时 [ " + strconv.Itoa(timeout) + " ] 不能小于 1 秒")
		return
	} else if thread < 1 {
		msgError("『PF』错误：线程 [ " + strconv.Itoa(thread) + " ] 不能小于 1 线程")
		return
	} else if !fileExist(inputFile) {
		msgError("『PF』错误：输入文件 [ " + inputFile + " ] 不存在")
		return
	}

	// 检查本地IP库是否存在
	/*
	if fileExist("qqwry.dat") {
		ipLibrary = true
		//msgSuccess("『PF』载入：本地IP库 [ qqwry.dat ]")
	} else {
		ipLibrary = false
		msgWarning("『PF』本地IP库 [ qqwry.dat ] 不存在\n")
	}
	*/

	// 读取列表文件
	msgError("『PF』正在读取代理文件...\n")
	list_,err = readFile(inputFile)
	if err != nil {
		msgError("『PF』错误：输入IP列表 [ "+inputFile+" ] 读取失败！")
		return
	}
	msgError("『PF』正在过滤重复代理...\n")
	list := SliceRemoveDuplicates(list_)

	if thread > len(list) {
		thread = len(list)
	}

	// 开始
	lip = localIP()
	times := int(time.Now().Unix())
	msgError("『PF』正在检测代理，请稍后...\n")
	runtime.GOMAXPROCS(runtime.NumCPU())
	var w sync.WaitGroup
	for _,ip := range list {
		w.Add(1)
		for runtime.NumGoroutine() > thread {}
		go proxyFiltering(ip, timeout, agreement, &w)
	}
	w.Wait()

	// 保存列表
	err = writeFile(outputFile, []byte(strings.Join(ipList , "\n")))
	if err != nil {
		msgError("『PF』错误：输出IP列表 [ "+outputFile+" ] 写出失败！")
		return
	}

	callClear()
	msgBlue("『ProxyFiltering』1.8+")
	msgViolet("TG: @DDoS_DataStation\n")
	msgWarning("==============================")
	msgWarning("『PF』载入代理：" + strconv.Itoa(len(list_)))
	msgWarning("『PF』重复代理：" + strconv.Itoa(repeatIP))
	msgWarning("『PF』存活代理：" + strconv.Itoa(anonymousIP+transparentIP))
	msgWarning("『PF』透明代理：" + strconv.Itoa(transparentIP))
	msgWarning("『PF』匿名代理：" + strconv.Itoa(anonymousIP))
	msgWarning("『PF』检测协议：" + agreement)
	msgWarning("『PF』检测协程：" + strconv.Itoa(thread))
	msgWarning("『PF』超时时限：" + strconv.Itoa(timeout))
	msgWarning("『PF』耗时(秒)：" + strconv.Itoa(int(time.Now().Unix())-times))
	msgWarning("==============================")
	msgSuccess("匿名代理已保存到：" + outputFile)
}