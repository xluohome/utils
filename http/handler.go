package http

import (
	"fmt"
	"github.com/last911/utils"
	"net/http"
	"net/http/httputil"
	neturl "net/url"
	"reflect"
	"strings"
	"time"
)

type ContentType int

const (
	NONE ContentType = iota
	HTML
	JSON
	XML
	PLAIN
)

var contentType = [...]string{
	"text/plain; charset=utf-8",
	"text/html; charset=utf-8",
	"application/json; charset=utf-8",
	"application/xml; charset=utf-8",
	"text/plain; charset=utf-8",
}

func (this ContentType) String() string {
	return contentType[this]
}

type HandlerType int

const (
	REVERSE_PROXY HandlerType = iota
	CONTROLLER_HANDLER
)

type ResponseData struct {
	ContentType ContentType
	Code        int
	Data        interface{}
	Message     string
}

type ControllerInterface interface {
	BeforeAction() bool
	Action() *ResponseData
	AfterAction() *ResponseData
}

type Controller struct {
	Req       *http.Request
	Res       http.ResponseWriter
	Timestamp time.Time
}

func (this *Controller) Init(req *http.Request, res http.ResponseWriter) {
	this.Req = req
	this.Res = res
	this.Timestamp = time.Now()
}

func (this *Controller) BeforeAction() bool {
	return true
}

func (this *Controller) Action() *ResponseData {
	return nil
}

func (this *Controller) AfterAction() *ResponseData {
	return nil
}

func (this *Controller) Redirect(url string, code int) {
	this.Res.Header().Set("location", url)
	this.Res.WriteHeader(code)
}

func (this *Controller) GetRequestIp() string {
	return strings.Split(this.Req.RemoteAddr, ":")[0]
}

func (this *Controller) GetCookie(name string) string {
	cookie, err := this.Req.Cookie(name)
	if err != nil {
		return ""
	}

	return cookie.Value
}

func (this *Controller) DelCookie(name string) {
	this.SetCookie(name, "", -1)
}

func (this *Controller) SetCookie(name, value string, v ...interface{}) {
	cookie := http.Cookie{Name: name, Value: value}
	if len(v) > 0 {
		var expires int64
		switch i := v[0].(type) {
		case int:
			expires = int64(i)
		case int32:
			expires = int64(i)
		case int64:
			expires = i
		}

		cookie.Expires = time.Now().Add(time.Duration(expires) * time.Second)
		switch {
		case expires > 0:
			cookie.MaxAge = int(expires)
		case expires < 0:
			cookie.MaxAge = 0
		}
	}

	if len(v) > 1 {
		cookie.Path = v[1].(string)
	}

	if len(v) > 2 {
		cookie.Domain = v[2].(string)
	}

	if len(v) > 3 {
		cookie.Secure = true
	}

	if len(v) > 4 {
		cookie.HttpOnly = true
	}

	this.Res.Header().Set("Set-Cookie", cookie.String())
}

// copy from net/http/httputil/reverseproxy.go
func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

// 0 targetPath + requestPath 1 requestPath 2 targetPath 3 requestPath - targetPath
func NewReverseProxy(rawUrl string, mode int) (*httputil.ReverseProxy, error) {
	target, err := neturl.Parse(rawUrl)
	if err != nil {
		return nil, err
	}

	targetQuery := target.RawQuery
	director := func(req *http.Request) {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		switch mode {
		case 0:
			req.URL.Path = singleJoiningSlash(target.Path, req.URL.Path)
		case 2:
			req.URL.Path = target.Path
		case 3:
			req.URL.Path = strings.TrimLeft(req.URL.Path, target.Path)
			if strings.Index(req.URL.Path, "/") != 0 {
				req.URL.Path = "/" + req.URL.Path
			}
		}
		if targetQuery == "" || req.URL.RawQuery == "" {
			req.URL.RawQuery = targetQuery + req.URL.RawQuery
		} else {
			req.URL.RawQuery = targetQuery + "&" + req.URL.RawQuery
		}
	}
	return &httputil.ReverseProxy{Director: director}, nil
}

type AppHandler struct {
	handlers        map[string]reflect.Type
	routes          map[string]HandlerType
	proxys          map[string]*httputil.ReverseProxy
	contentType     ContentType
	notFoundHandler reflect.Type
}

func NewAppHandler() *AppHandler {
	return &AppHandler{handlers: make(map[string]reflect.Type), proxys: make(map[string]*httputil.ReverseProxy), contentType: NONE, routes: make(map[string]HandlerType)}
}

func (this *AppHandler) SetContentType(contentType ContentType) {
	this.contentType = contentType
}

func (this *AppHandler) AddHandler(path string, i ControllerInterface) {
	this.handlers[path] = reflect.Indirect(reflect.ValueOf(i)).Type()
	this.routes[path] = CONTROLLER_HANDLER
}

func (this *AppHandler) AddReverseProxy(path string, backend *httputil.ReverseProxy) {
	this.proxys[path] = backend
	this.routes[path] = REVERSE_PROXY
}

func (this *AppHandler) SetNotFoundHandler(handler ControllerInterface) {
	this.notFoundHandler = reflect.Indirect(reflect.ValueOf(handler)).Type()
}

// extends http.Handler
func (this *AppHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	defer func() {
		if err := recover(); err != nil {
			var data *ResponseData
			switch err.(type) {
			case *ResponseData:
				data = err.(*ResponseData)
			default:
				data = &ResponseData{Code: 500, Message: "Unknown:" + fmt.Sprint(err)}
			}

			if data.ContentType == NONE {
				data.ContentType = this.contentType
			}

			rw.Header().Set("Content-Type", data.ContentType.String())
			var str string
			switch data.ContentType {
			case JSON:
				d := make(map[string]interface{})
				if data.Code == 0 {
					d["code"] = 0
					d["data"] = data.Data
				} else {
					d["code"] = data.Code
					d["message"] = data.Message
				}
				str = utils.JsonEncode(d)
			default:
				if data.Code == 0 {
					str = fmt.Sprint(data.Data)
				} else {
					str = data.Message
				}
			}
			rw.Write([]byte(str))
		}
	}()
	req.ParseForm()

	urlPath := strings.TrimSpace(req.URL.Path)[1:]
	var r string
	if urlPath == "" {
		r = "/"
	} else {
		for route, _ := range this.routes {
			if route == "/" {
				continue
			}
			if strings.Index(urlPath, route[1:]) == 0 {
				r = route
				break
			}
		}
	}

	handlerFunc := func(t reflect.Type) {
		instance := reflect.New(t)
		params := make([]reflect.Value, 2)
		params[0] = reflect.ValueOf(req)
		params[1] = reflect.ValueOf(rw)

		instance.MethodByName("Init").Call(params)

		values := instance.MethodByName("BeforeAction").Call(make([]reflect.Value, 0))
		if values[0].Bool() {
			values = instance.MethodByName("Action").Call(make([]reflect.Value, 0))
			afterValues := instance.MethodByName("AfterAction").Call(make([]reflect.Value, 0))
			var data *ResponseData
			if afterValues[0].IsNil() {
				if !values[0].IsNil() {
					data = values[0].Interface().(*ResponseData)
				}
			} else {
				data = afterValues[0].Interface().(*ResponseData)
			}

			if data != nil {
				panic(data)
			}
		}
	}

	if r == "" {
		// 404
		if this.notFoundHandler != nil {
			handlerFunc(this.notFoundHandler)
		} else {
			panic(&ResponseData{Code: 404, Message: "Not Found"})
		}
	}

	if this.routes[r] == REVERSE_PROXY {
		this.proxys[r].ServeHTTP(rw, req)
	} else {
		t := this.handlers[r]
		handlerFunc(t)
	}
}
