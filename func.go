package utils

// 常用的函数

import (
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
	"io"
	"math/rand"
	"net"
	"reflect"
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
	l := len(params)

	isEncode := false
	key := ""
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
		return ""
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

	return ""
}

// 编码JSON
func JsonEncode(m interface{}) string {
	b, err := json.Marshal(m)
	if err != nil {
		LogError.Write("Json Encode Error:%s", err.Error())
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
		LogError.Write("Json Decode Error:%s", err.Error())
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
		LogError.Write("get local ip error:%s", err.Error())
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
