package utils

// 日志记录，暂时只有输出，没有写文件

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
    Level LogLevel // 对象LOG的输出等级
}

var (
    WriteLogLevel = TRACE // 默认输出所有的信息
    LogTrace = Log{Level: TRACE}
    LogDebug = Log{Level: DEBUG}
    LogInfo = Log{Level: INFO}
    LogWarn = Log{Level: WARN}
    LogError = Log{Level: ERROR}
    LogFatal = Log{Level: FATAL}
    ShowDebug = true // 是否显示debug信息
)

func (this *Log) Write(format string, v ...interface{}) {
    if this.Level >= WriteLogLevel {
        // 需要输出日志
        _, file, line, _ := runtime.Caller(1)
        t := time.Now().Format("2006-01-02 15:04:05")

        if ShowDebug {
            format = fmt.Sprintf("[%s] %s file:%s line:%d %s\n", t, this.Level.String(), file, line, format)
        } else {
            format = fmt.Sprintf("[%s] %s %s\n", t, this.Level.String(), format)
        }

        fmt.Printf(format, v...)

        if this.Level == FATAL {
            // 需要退出程序
            os.Exit(0)
        }
    }
}
