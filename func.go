package utils

// 常用的函数

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"io/ioutil"
	"math/rand"
	"mime/multipart"
	"net"
	"net/http"
	httpurl "net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// 随机数字 0 <= n < max
func Rand(max int) int {
	rand.Seed(time.Now().UnixNano())
	return rand.Intn(max)
}

// 随机一个数字 min <= n < max
func RandInt(min int, max int) int {
	if max == min {
		return min
	}
	rand.Seed(time.Now().UnixNano())
	if max < min {
		min, max = max, min
	}
	return min + rand.Intn(max-min)
}

// 随机数字 0 <= n < max
func Rand64(max int64) int64 {
	rand.Seed(time.Now().UnixNano())
	return rand.Int63n(max)
}

// 随机一个数字 min <= n < max
func RandInt64(min int64, max int64) int64 {
	if max == min {
		return min
	}
	rand.Seed(time.Now().UnixNano())
	if max < min {
		min, max = max, min
	}
	return min + rand.Int63n(max-min)
}

// 字符串反转
func Reverse(s string) string {
	b := []byte(s)
	n := ""
	for i := len(b); i > 0; i-- {
		n += string(b[i-1])
	}
	return string(n)
}

// 随机一个数组值
func RandArray(arr []string) string {
	return arr[Rand(len(arr))]
}

// 转换成整型
func Atoi(s string, d ...int) int {
	i, err := strconv.Atoi(s)
	if err != nil {
		if len(d) > 0 {
			return d[0]
		} else {
			return 0
		}
	}

	return i
}

// 转换成整型int64
func Atoi64(s string, d ...int64) int64 {
	i, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		if len(d) > 0 {
			return d[0]
		} else {
			return 0
		}
	}

	return i
}

// 转换成float32整型
func Atof(s string, d ...float32) float32 {
	f, err := strconv.ParseFloat(s, 32)
	if err != nil {
		if len(d) > 0 {
			return d[0]
		} else {
			return 0
		}
	}

	return float32(f)
}

// 转换成整型float64
func Atof64(s string, d ...float64) float64 {
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		if len(d) > 0 {
			return d[0]
		} else {
			return 0
		}
	}

	return f
}

// md5
func Md5Sum(text string) string {
	h := md5.New()
	io.WriteString(h, text)
	return fmt.Sprintf("%x", h.Sum(nil))
}

func Crc32(text string) string {
	h := crc32.NewIEEE()
	io.WriteString(h, text)
	return fmt.Sprintf("%d", h.Sum32())
}

// rsa 加密
func RsaEncode(b, rsaKey []byte) ([]byte, error) {
	block, _ := pem.Decode(rsaKey)
	if block == nil {
		return b, errors.New("key error")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return b, err
	}
	return rsa.EncryptPKCS1v15(crand.Reader, pub.(*rsa.PublicKey), b)
}

// rsa 解密
func RsaDecode(b, rsaKey []byte) ([]byte, error) {
	block, _ := pem.Decode(rsaKey)
	if block == nil {
		return b, errors.New("key error")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return b, err
	}
	return rsa.DecryptPKCS1v15(crand.Reader, priv, b)
}

// 判断是否正确的ip地址
func IsIp(ip string) bool {
	ips := strings.Split(ip, ".")
	if len(ips) != 4 {
		return false
	}
	for _, v := range ips {
		i := Atoi(v, -1)
		if i < 0 || i > 255 {
			return false
		}
	}

	return true
}

// Base64encode
func Base64Encode(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func Base64Decode(str string) []byte {
	var b []byte
	var err error
	x := len(str) * 3 % 4
	switch {
	case x == 2:
		str += "=="
	case x == 1:
		str += "="
	}
	if b, err = base64.StdEncoding.DecodeString(str); err != nil {
		return b
	}

	return b
}

// 生成一个数组 不包括n
func Range(m, n int) (b []int) {
	if m >= n {
		return b
	}

	for i := m; i < n; i++ {
		b = append(b, i)
	}

	return b
}

// 加解密函数 根据dz的Authcode改写的go版本
// params[0] 加密or解密 bool true：加密 false：解密 默认false
// params[1] 秘钥
// params[2] 加密：过期时间
// params[3] 动态秘钥长度 默认：4位 不能大于32位
func Authcode(text string, params ...interface{}) string {
	defer func() {
		if err := recover(); err != nil {
			LogInfo.Write("authcode error:%#v", err)
		}
	}()

	l := len(params)

	isEncode := false
	key := "abcdefghijklmnopqrstuvwxyz13550009575"
	expiry := 0
	cKeyLen := 4

	if l > 0 {
		isEncode = params[0].(bool)
	}

	if l > 1 {
		key = params[1].(string)
	}

	if l > 2 {
		expiry = params[2].(int)
		if expiry < 0 {
			expiry = 0
		}
	}

	if l > 3 {
		cKeyLen = params[3].(int)
		if cKeyLen < 0 {
			cKeyLen = 0
		}
	}
	if cKeyLen > 32 {
		cKeyLen = 32
	}

	timestamp := time.Now().Unix()

	// md5加密key
	mKey := Md5Sum(key)

	// 参与加密的
	keyA := Md5Sum(mKey[0:16])
	// 用于验证数据有效性的
	keyB := Md5Sum(mKey[16:])
	// 动态部分
	var keyC string
	if cKeyLen > 0 {
		if isEncode {
			// 加密的时候，动态获取一个秘钥
			keyC = Md5Sum(fmt.Sprint(timestamp))[32-cKeyLen:]
		} else {
			// 解密的时候从头部获取动态秘钥部分
			keyC = text[0:cKeyLen]
		}
	}

	// 加入了动态的秘钥
	cryptKey := keyA + Md5Sum(keyA+keyC)
	// 秘钥长度
	keyLen := len(cryptKey)
	if isEncode {
		// 加密 前10位是过期验证字符串 10-26位字符串验证
		var d int64
		if expiry > 0 {
			d = timestamp + int64(expiry)
		}
		text = fmt.Sprintf("%010d%s%s", d, Md5Sum(text + keyB)[0:16], text)
	} else {
		// 解密
		text = string(Base64Decode(text[cKeyLen:]))
	}

	// 字符串长度
	textLen := len(text)
	if textLen <= 0 {
		panic(fmt.Sprintf("auth[%s]textLen<=0", text))
	}

	// 密匙簿
	box := Range(0, 256)
	// 对称算法
	var rndKey []int
	cryptKeyB := []byte(cryptKey)
	for i := 0; i < 256; i++ {
		pos := i % keyLen
		rndKey = append(rndKey, int(cryptKeyB[pos]))
	}

	j := 0
	for i := 0; i < 256; i++ {
		j = (j + box[i] + rndKey[i]) % 256
		box[i], box[j] = box[j], box[i]
	}

	textB := []byte(text)
	a := 0
	j = 0
	var result []byte
	for i := 0; i < textLen; i++ {
		a = (a + 1) % 256
		j = (j + box[a]) % 256
		box[a], box[j] = box[j], box[a]
		result = append(result, byte(int(textB[i])^(box[(box[a]+box[j])%256])))
	}

	if isEncode {
		return keyC + strings.Replace(Base64Encode(result), "=", "", -1)
	}

	// 获取前10位，判断过期时间
	d := Atoi64(string(result[0:10]), 0)
	if (d == 0 || d-timestamp > 0) && string(result[10:26]) == Md5Sum(string(result[26:]) + keyB)[0:16] {
		return string(result[26:])
	}

	panic(fmt.Sprintf("auth[%s]", text))

	return ""
}

// 编码JSON
func JsonEncode(m interface{}) string {
	b, err := json.Marshal(m)
	if err != nil {
		LogInfo.Write("Json Encode Error:%s", err.Error())
		return ""
	}
	return string(b)
}

// 解码JSON
func JsonDecode(str string, v ...interface{}) interface{} {
	var m interface{}
	if len(v) > 0 {
		m = v[0]
	} else {
		m = make(map[string]interface{})
	}

	err := json.Unmarshal([]byte(str), &m)
	if err != nil {
		LogInfo.Write("Json Decode Error:%s", err.Error())
		return nil
	}

	return m
}

func HashHmac(data, key string) string {
	mac := hmac.New(sha1.New, []byte(key))
	mac.Write([]byte(data))
	return fmt.Sprintf("%x", mac.Sum(nil))
}

func HashHmacRaw(data, key string) string {
	mac := hmac.New(sha1.New, []byte(key))
	mac.Write([]byte(data))
	return fmt.Sprintf("%s", mac.Sum(nil))
}

func TimeFormat(t time.Time, f int) (timeStr string) {
	switch f {
	case 0:
		timeStr = t.Format("2006-01-02 15:04:05")
	case 1:
		timeStr = t.Format("2006-01-02")
	case 2:
		timeStr = t.Format("20060102150405")
	case 3:
		timeStr = t.Format("15:04:05")
	case 4:
		timeStr = t.Format("2006-01-02 15:04")
	}

	return
}

func Now(f int) string {
	return TimeFormat(time.Now(), f)
}

func GetLocalIp() (ip string) {
	conn, err := net.Dial("udp", "google.com:80")
	if err != nil {
		LogInfo.Write("get local ip error:%s", err.Error())
		return
	}
	defer conn.Close()
	ip = strings.Split(conn.LocalAddr().String(), ":")[0]

	return
}

func StructToMap(data interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	elem := reflect.ValueOf(data).Elem()
	size := elem.NumField()

	for i := 0; i < size; i++ {
		field := elem.Type().Field(i).Name
		value := elem.Field(i).Interface()
		result[field] = value
	}

	return result
}

func Keys(m map[string]interface{}) []string {
	var keys []string
	for k, _ := range m {
		keys = append(keys, k)
	}

	return keys
}

func Values(m map[string]interface{}) []interface{} {
	var values []interface{}
	for _, v := range m {
		values = append(values, v)
	}

	return values
}

func IsEmpty(val interface{}) bool {
	v := reflect.ValueOf(val)

	switch v.Kind() {
	case reflect.Bool:
		return val.(bool) == false
	case reflect.String:
		return val.(string) == ""
	case reflect.Array:
		fallthrough
	case reflect.Slice:
		fallthrough
	case reflect.Map:
		return v.Len() == 0
	default:
		return v.Interface() == reflect.ValueOf(0).Interface() || v.Interface() == reflect.ValueOf(0.0).Interface()
	}

	return false
}

func Urlencode(str string) string {
	return base64.URLEncoding.EncodeToString([]byte(str))
}

func Urldecode(str string) string {
	b, e := base64.URLEncoding.DecodeString(str)
	if e != nil {
		LogInfo.Write("urldecode error:%s", e.Error())
		return ""
	}

	return string(b)
}

func Ip2long(ipstr string) (ip uint32) {
	r := `^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})`
	reg, err := regexp.Compile(r)
	if err != nil {
		return
	}
	ips := reg.FindStringSubmatch(ipstr)
	if ips == nil {
		return
	}

	ip1, _ := strconv.Atoi(ips[1])
	ip2, _ := strconv.Atoi(ips[2])
	ip3, _ := strconv.Atoi(ips[3])
	ip4, _ := strconv.Atoi(ips[4])

	if ip1 > 255 || ip2 > 255 || ip3 > 255 || ip4 > 255 {
		return
	}

	ip += uint32(ip1 * 0x1000000)
	ip += uint32(ip2 * 0x10000)
	ip += uint32(ip3 * 0x100)
	ip += uint32(ip4)

	return
}

func Long2ip(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", ip>>24, ip<<8>>24, ip<<16>>24, ip<<24>>24)
}

func IsMac(mac string) bool {
	if len(mac) != 17 {
		return false
	}

	r := `^(?i:[0-9a-f]{2}):(?i:[0-9a-f]{2}):(?i:[0-9a-f]{2}):(?i:[0-9a-f]{2}):(?i:[0-9a-f]{2}):(?i:[0-9a-f]{2})`
	reg, err := regexp.Compile(r)
	if err != nil {
		return false
	}
	m := reg.FindStringSubmatch(mac)
	if m == nil {
		return false
	}

	return true
}

func Exists(name string) bool {
	_, err := os.Stat(name)
	return !os.IsNotExist(err)
}

/**
 * http请求
 * string url 请求地址
 * string method 请求方法 支持post get
 * map params 请求的参数 \0@这样子的是上传文件
 * map header 请求头
 * bool rtn 是否返回结果 默认：true
 */
func HttpRequest(url, method string, args ...interface{}) (b bool, data string) {
	params := make(map[string]string)  // 请求参数
	headers := make(map[string]string) // header参数
	rtn := true                        // 是否返回

	argsLen := len(args)
	if argsLen > 0 {
		params = args[0].(map[string]string)
	}
	if argsLen > 1 {
		headers = args[1].(map[string]string)
	}
	if argsLen > 2 {
		rtn = args[2].(bool)
	}

	var req *http.Request
	var err error
	contentType := "application/x-www-form-urlencoded; charset=utf-8" // content-type

	if "GET" == strings.ToUpper(method) {
		// GET
		var queryString string
		for k, v := range params {
			queryString += "&" + k + "=" + v
		}
		if queryString != "" {
			if strings.Index(url, "?") != -1 {
				// 有参数
				url += queryString
			} else {
				// 无参数
				url += "?" + queryString[1:]
			}
		}

		req, err = http.NewRequest("GET", url, nil)
	} else {
		// POST
		// 检查是否有上传的文件
		var isFile bool // 是否有文件上传
		for _, v := range params {
			if strings.Index(v, "\x00@") == 0 {
				// 那么有上传文件
				isFile = true
				break
			}
		}
		if isFile {
			bodyBuf := new(bytes.Buffer)
			bodyWriter := multipart.NewWriter(bodyBuf)

			for key, value := range params {
				if strings.Index(value, "\x00@") == 0 {
					value = strings.Replace(value, "\x00@", "", -1)
					fileWriter, e := bodyWriter.CreateFormFile(key, filepath.Base(value))
					if e != nil {
						LogWarn.Write("request[%s]upload file error:%s", url, e.Error())
						return
					}
					fh, e := os.Open(value)
					if e != nil {
						LogWarn.Write("request[%s]open file error:%s", url, e.Error())
						return
					}
					defer fh.Close()

					//iocopy
					_, e = io.Copy(fileWriter, fh)
					if e != nil {
						LogWarn.Write("request[%s]copy file error:%s", url, e.Error())
						return
					}
				} else {
					bodyWriter.WriteField(key, value)
				}
			}

			// 注：这个太重要了，居然之前没有注意到，如果不关闭，那么服务端是收不到提交文件的。
			// Important if you do not close the multipart writer you will not have a terminating boundry
			bodyWriter.Close()
			contentType = bodyWriter.FormDataContentType()
			req, err = http.NewRequest("POST", url, bodyBuf)
		} else {
			v := httpurl.Values{}
			for key, value := range params {
				v.Set(key, value)
			}
			req, err = http.NewRequest("POST", url, strings.NewReader(v.Encode()))
		}
	}

	if err != nil {
		LogWarn.Write("new request[%s]error:%s", url, err.Error())
		return
	}

	// 加入头
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	//req.Header.Set("Connection", "close") // 关闭连接
	req.Header.Set("Content-Type", contentType)

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		LogWarn.Write("do request[%s]error:%s", url, err.Error())
		return
	}
	defer res.Body.Close()

	if rtn {
		// 需要返回
		bData, err := ioutil.ReadAll(res.Body)
		if err != nil {
			LogWarn.Write("read request[%s]body error:%s", url, err.Error())
			return
		}

		b = true
		data = string(bData)
	} else {
		// 不需要返回
		b = true
	}

	return
}

// Max returns the larger of a and b.
func Max(a, b int) int {
	if a > b {
		return a
	}

	return b
}

// Min returns the smaller of a and b.
func Min(a, b int) int {
	if a < b {
		return a
	}

	return b
}

// UMax returns the larger of a and b.
func UMax(a, b uint) uint {
	if a > b {
		return a
	}

	return b
}

// UMin returns the smaller of a and b.
func UMin(a, b uint) uint {
	if a < b {
		return a
	}

	return b
}

// MaxByte returns the larger of a and b.
func MaxByte(a, b byte) byte {
	if a > b {
		return a
	}

	return b
}

// MinByte returns the smaller of a and b.
func MinByte(a, b byte) byte {
	if a < b {
		return a
	}

	return b
}

// MaxInt8 returns the larger of a and b.
func MaxInt8(a, b int8) int8 {
	if a > b {
		return a
	}

	return b
}

// MinInt8 returns the smaller of a and b.
func MinInt8(a, b int8) int8 {
	if a < b {
		return a
	}

	return b
}

// MaxUint16 returns the larger of a and b.
func MaxUint16(a, b uint16) uint16 {
	if a > b {
		return a
	}

	return b
}

// MinUint16 returns the smaller of a and b.
func MinUint16(a, b uint16) uint16 {
	if a < b {
		return a
	}

	return b
}

// MaxInt16 returns the larger of a and b.
func MaxInt16(a, b int16) int16 {
	if a > b {
		return a
	}

	return b
}

// MinInt16 returns the smaller of a and b.
func MinInt16(a, b int16) int16 {
	if a < b {
		return a
	}

	return b
}

// MaxUint32 returns the larger of a and b.
func MaxUint32(a, b uint32) uint32 {
	if a > b {
		return a
	}

	return b
}

// MinUint32 returns the smaller of a and b.
func MinUint32(a, b uint32) uint32 {
	if a < b {
		return a
	}

	return b
}

// MaxInt32 returns the larger of a and b.
func MaxInt32(a, b int32) int32 {
	if a > b {
		return a
	}

	return b
}

// MinInt32 returns the smaller of a and b.
func MinInt32(a, b int32) int32 {
	if a < b {
		return a
	}

	return b
}

// MaxUint64 returns the larger of a and b.
func MaxUint64(a, b uint64) uint64 {
	if a > b {
		return a
	}

	return b
}

// MinUint64 returns the smaller of a and b.
func MinUint64(a, b uint64) uint64 {
	if a < b {
		return a
	}

	return b
}

// MaxInt64 returns the larger of a and b.
func MaxInt64(a, b int64) int64 {
	if a > b {
		return a
	}

	return b
}

// MinInt64 returns the smaller of a and b.
func MinInt64(a, b int64) int64 {
	if a < b {
		return a
	}

	return b
}

// 是否在列表中
func InArray(l []string, v string) bool {
	for _, val := range l {
		if val == v {
			return true
		}
	}

	return false
}

func Trim(str string) string {
	return strings.Trim(str, " \r\n\t")
}

func Split(str string) []string {
	re := regexp.MustCompile("[ \t]+")
	return re.Split(str, -1)
}

func CopyFile(dstName, srcName string) (written int64, err error) {
	src, err := os.Open(srcName)
	if err != nil {
		return 0, err
	}
	defer src.Close()
	dst, err := os.OpenFile(dstName, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return 0, err
	}
	defer dst.Close()
	return io.Copy(dst, src)
}

func AbsolutePath() string {
	file, err := exec.LookPath(os.Args[0])
	if err != nil {
		return "./"
	}
	path, _ := filepath.Abs(file)
	if err != nil {
		return "./"
	}

	return filepath.Dir(path) + "/"
}
