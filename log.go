package utils

import (
	"fmt"
	"log"
	"os"
	"runtime"
	"time"
)

type LogLevel int

const (
	TRACE LogLevel = iota
	DEBUG
	INFO
	WARN
	ERROR
	FATAL
)

var logLevel = [...]string{
	"TRACE",
	"DEBUG",
	"INFO",
	"WARN",
	"ERROR",
	"FATAL",
}

func (this LogLevel) String() string {
	return logLevel[this]
}

type Log struct {
	*log.Logger
	Level    LogLevel // 对象LOG的输出等级
	LogLevel LogLevel // 需要输出的等级
}

func (this *Log) Write(format string, v ...interface{}) {
	if this.Level >= this.LogLevel {
		// 需要输出日志
		_, file, line, _ := runtime.Caller(1)
		t := time.Now()
		format = fmt.Sprintf("[%s] %s file:%s line:%d %s\n", t.Format("2006-01-02 15:04:05"), this.Level.String(), file, line, format)

		this.Printf(format, v...)

		if this.Level == FATAL {
			// 需要退出程序
			os.Exit(0)
		}
	}
}
