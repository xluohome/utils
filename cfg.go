package utils

import (
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"strings"
	"time"
)

type cfgValue struct {
	value  string
	status int // 状态 1 删除 2 修改/添加 3 不变
}

type Cfg struct {
	data    map[string]cfgValue // 键值数据map
	content []string            // 保存整个文本
	file    string              // 保存的文件名
}

func (cfg *Cfg) Get(name string) string {
	return cfg.data[name].value
}

func (cfg *Cfg) Set(name, value string) {
	cfg.data[name] = cfgValue{status: 2, value: value}
}

func (cfg *Cfg) Del(name string) {
	if cfg.data[name].status != 0 {
		cfg.data[name] = cfgValue{status: 1, value: cfg.data[name].value}
	}
}

func (cfg *Cfg) Save() error {
	if cfg.file == "" {
		// 随机一个
		cfg.file = fmt.Sprintf("%d.txt", time.Now().Unix())
	}

	contents := cfg.content
	for key, value := range cfg.data {
		switch value.status {
		case 1:
			// 删除
			contents = cfg.handleContent(contents, key, value.value, true)
		case 2:
			// 添加、修改
			contents = cfg.handleContent(contents, key, value.value, false)
		}
	}

	// 去掉最后的\n
	content := strings.TrimLeft(strings.TrimRight(strings.Join(contents, "\n"), "\n"), "\n")

	f, err := os.Create(cfg.file)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.WriteString(content)
	if err != nil {
		return err
	}

	return nil
}

func (cfg *Cfg) handleContent(content []string, key, value string, isDel bool) []string {
	for i, line := range content {
		if strings.Index(line, key+" ") == 0 {
			if isDel {
				// 删除
				return append(content[0:i], content[i+1:]...)
			} else {
				// 修改 添加
				content[i] = key + " " + value
				return content
			}
		}
	}

	// 没有返回，那么表示没有搜索到，
	if !isDel {
		// 又不是删除，那么添加吧
		return append(content, key+" "+value)
	}

	return content
}

func CfgFromString(str string) (cfg Cfg) {
	split := regexp.MustCompile(`(\s)+`)
	content := strings.Split(str, "\n")
	cfg.data = make(map[string]cfgValue)
	for _, line := range content {
		line = strings.TrimSpace(line)
		if line != "" && strings.Index(line, "#") != 0 {
			// 不是注释
			strs := split.Split(line, 2)
			if len(strs) == 2 {
				cfg.data[strs[0]] = cfgValue{value: strs[1], status: 3}
			} else if len(strs) == 1 {
				line += " "
				cfg.data[strs[0]] = cfgValue{value: "", status: 3}
			}
		}
		cfg.content = append(cfg.content, line)
	}

	return
}

func CfgFromFile(file string) (cfg Cfg) {
	b, err := ioutil.ReadFile(file)
	if err != nil {
		return
	}
	cfg = CfgFromString(string(b))
	cfg.file = file
	return
}
