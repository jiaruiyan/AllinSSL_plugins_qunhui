package lib

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Client struct {
	UserName string
	Password string
	Scheme   string
	Host     string
	Port     int64
	auth     Auth // 用于存储登录后的认证信息
}
type SSL struct {
	pem string
	key string
}
type Auth struct {
	account      string
	deviceId     string
	ikMessage    string
	isPortalPort bool
	sid          string // 登录会话ID
	synoToken    string // 用于后续请求的令牌
}

// 登录响应的错误结构
type loginError struct {
	Code int `json:"code"`
}

// 登录响应的成功数据结构
type loginData struct {
	Did          string `json:"did"`
	IsPortalPort bool   `json:"is_portal_port"`
	Sid          string `json:"sid"`
	SynoToken    string `json:"synotoken"`
}

// 完整的登录响应结构
type loginResponse struct {
	Error   *loginError `json:"error,omitempty"` // 只在失败时存在
	Data    *loginData  `json:"data,omitempty"`  // 只在成功时存在
	Success bool        `json:"success"`
}

// cert
type CertificateResponse struct {
	Data    CertificateData `json:"data"`
	Success bool            `json:"success"`
}

type CertificateData struct {
	Certificates []Certificate `json:"certificates"`
}

type Certificate struct {
	Desc                string        `json:"desc"`
	ID                  string        `json:"id"`
	IsBroken            bool          `json:"is_broken"`
	IsDefault           bool          `json:"is_default"`
	Issuer              Issuer        `json:"issuer"`
	KeyTypes            string        `json:"key_types"`
	Renewable           bool          `json:"renewable"`
	Services            []Service     `json:"services"`
	SignatureAlgorithm  string        `json:"signature_algorithm"`
	Subject             Subject       `json:"subject"`
	UserDeletable       bool          `json:"user_deletable"`
	ValidFrom           string        `json:"valid_from"`
	ValidTill           string        `json:"valid_till"`
	SelfSignedCacrtInfo *SelfSignedCA `json:"self_signed_cacrt_info,omitempty"` // 可选字段
}

type Issuer struct {
	CommonName   string `json:"common_name"`
	Country      string `json:"country"`
	Organization string `json:"organization"`
	City         string `json:"city,omitempty"` // 可选字段
}

type Service struct {
	DisplayName     string `json:"display_name"`
	DisplayNameI18n string `json:"display_name_i18n,omitempty"`
	IsPkg           bool   `json:"isPkg"`
	MultipleCert    bool   `json:"multiple_cert,omitempty"`
	Owner           string `json:"owner"`
	Service         string `json:"service"`
	Subscriber      string `json:"subscriber"`
	UserSetable     bool   `json:"user_setable,omitempty"`
}

type Subject struct {
	CommonName   string   `json:"common_name"`
	SubAltName   []string `json:"sub_alt_name"`
	City         string   `json:"city,omitempty"` // 可选字段
	Country      string   `json:"country,omitempty"`
	Organization string   `json:"organization,omitempty"`
}

type SelfSignedCA struct {
	Issuer  Issuer  `json:"issuer"`
	Subject Subject `json:"subject"`
}

// cert结束

// FileInfo 包含文件路径和对应的表单key
type FileInfo struct {
	FilePath string // 文件路径
	Key      string // 表单中的key
}

func (qunhuiClient *Client) Login() error {
	// 创建自定义HTTP客户端
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:    10,
			MaxConnsPerHost: 10,
			IdleConnTimeout: 30 * time.Second,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // 忽略证书验证
			},
		},
	}

	qunhuiUrl := fmt.Sprintf(
		"%s://%s:%d/webapi/auth.cgi?api=SYNO.API.Auth&version=7&method=login&account=%s&passwd=%s&enable_syno_token=yes",
		qunhuiClient.Scheme,
		qunhuiClient.Host,
		qunhuiClient.Port,
		qunhuiClient.UserName,
		qunhuiClient.Password,
	)

	// 发送GET请求
	resp, err := client.Get(qunhuiUrl)
	if err != nil {
		return fmt.Errorf("请求发生错误%v", err)
	}
	// 重要：记得关闭响应体
	defer resp.Body.Close()
	// 读取响应体内容
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("读取响应体失败")
	}
	// 解析JSON响应
	var loginResp loginResponse
	if err := json.Unmarshal(body, &loginResp); err != nil {
		return fmt.Errorf("解析响应失败: %w, 响应内容: %s", err, string(body))
	}
	// 处理登录结果
	if !loginResp.Success && loginResp.Error != nil {
		return fmt.Errorf("登录失败，错误代码: %d", loginResp.Error.Code)
	}
	if loginResp.Success && loginResp.Data != nil {
		// 保存登录信息到Client的auth字段
		qunhuiClient.auth.sid = loginResp.Data.Sid
		qunhuiClient.auth.synoToken = loginResp.Data.SynoToken
		qunhuiClient.auth.isPortalPort = loginResp.Data.IsPortalPort
		qunhuiClient.auth.deviceId = loginResp.Data.Did
	}
	return nil
}

// GetAuth 获取当前的认证信息
func (qunhuiClient *Client) GetAuth() Auth {
	return qunhuiClient.auth
}
func (qunhuiClient *Client) Certificate(keyContent string, certContent string, id string, asDefault bool) error {
	// 检查认证信息是否有效
	if qunhuiClient.auth.synoToken == "" || qunhuiClient.auth.sid == "" {
		return fmt.Errorf("缺少必要的认证信息，请先登录")
	}
	//transport := &http.Transport{
	//	MaxIdleConns:    10,
	//	MaxConnsPerHost: 10,
	//	IdleConnTimeout: 30 * time.Second,
	//}
	//proxy, err := url.Parse("http://10.168.1.104:9000")
	//if err == nil {
	//	transport.Proxy = http.ProxyURL(proxy)
	//}
	qunhuiUrl := fmt.Sprintf(
		"%s://%s:%d/webapi/entry.cgi?api=SYNO.Core.Certificate&method=import&version=1&SynoToken=%s",
		qunhuiClient.Scheme,
		qunhuiClient.Host,
		qunhuiClient.Port,
		qunhuiClient.auth.synoToken,
	)
	// 创建请求体缓冲区
	bodyBuffer := &bytes.Buffer{}
	writer := multipart.NewWriter(bodyBuffer)
	defer writer.Close()
	// 处理 key 内容 - 创建临时文件
	keyTempFile, err := CreateNamedTempFile(keyContent, fmt.Sprintf("key-%d.pem", time.Now().UnixMilli()))
	if err != nil {
		return fmt.Errorf("创建key临时文件失败: %w", err)
	}

	// 处理 cert 内容 - 创建临时文件
	certTempFile, err := CreateNamedTempFile(certContent, fmt.Sprintf("cert-%d.crt", time.Now().UnixMilli()))
	if err != nil {
		return fmt.Errorf("创建cert临时文件失败: %w", err)
	}

	// 初始化时直接指定键值对
	asDefaults := ""
	if asDefault {
		asDefaults = "true"
	}
	reqParams := map[string]string{
		"id":         id,
		"desc":       fmt.Sprintf("ymwl-amen:AllinSSL@%s", time.Now().UTC()),
		"as_default": asDefaults,
	}

	files := []FileInfo{
		{Key: "key", FilePath: keyTempFile.Name()},
		{Key: "cert", FilePath: certTempFile.Name()},
	}
	header := map[string]string{
		"Cookie": fmt.Sprintf("id=%s", qunhuiClient.auth.sid),
	}
	resp, err := uploadMultipleFilesAndParams(qunhuiUrl, files, reqParams, header)
	defer os.Remove(keyTempFile.Name()) // 确保临时文件会被删除
	defer os.Remove(certTempFile.Name())
	if err != nil {
		return err
	}

	// 解析响应
	var result map[string]interface{}
	if err := json.Unmarshal(resp, &result); err != nil {
		//fmt.Printf("响应内容: %s\n", string(resp))
		return fmt.Errorf("解析响应失败: %w", err)
	}
	// 判断是否成功
	success, ok := result["success"].(bool)
	if !ok || !success {
		return fmt.Errorf("上传证书失败，响应: %v", result)
	}
	return nil
}
func (qunhuiClient *Client) CrtList() (*CertificateResponse, error) {
	// 请求URL
	qunhuiUrl := fmt.Sprintf("%s://%s:%d/webapi/entry.cgi",
		qunhuiClient.Scheme,
		qunhuiClient.Host,
		qunhuiClient.Port,
	)
	// 准备表单数据
	formData := url.Values{
		"api":     {"SYNO.Core.Certificate.CRT"},
		"version": {"1"},
		"method":  {"list"},
	}
	// 创建POST请求
	req, err := http.NewRequest("POST", qunhuiUrl, strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %v", err)
	}
	// 设置请求头，指定内容类型为application/x-www-form-urlencoded
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// 添加用户代理，模拟浏览器请求
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36")
	req.Header.Set("Cookie", fmt.Sprintf("id=%s", qunhuiClient.auth.sid))
	req.Header.Set("X-SYNO-TOKEN", qunhuiClient.auth.synoToken)
	// 发送请求
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:    10,
			MaxConnsPerHost: 10,
			IdleConnTimeout: 30 * time.Second,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // 忽略证书验证
			},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("发送请求失败: %v", err)
	}
	defer resp.Body.Close()
	// 检查响应状态码
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("请求失败，状态码: %d, 响应内容: %s", resp.StatusCode, string(body))
	}
	// 读取响应内容
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应内容失败: %v", err)
	}
	// 解析JSON响应
	var certResponse CertificateResponse
	if err := json.Unmarshal(body, &certResponse); err != nil {
		return nil, fmt.Errorf("解析JSON失败: %v, 原始数据: %s", err, string(body))
	}
	// 是否获取到数据
	if certResponse.Success == false {
		return nil, fmt.Errorf("获取证书列表失败: %v, 原始数据: %s", err, string(body))
	}
	return &certResponse, nil
}

// CreateNamedTempFile 创建指定名称的临时文件（含正确后缀）
// 避免使用os.CreateTemp的随机字符串，确保文件名符合服务要求
func CreateNamedTempFile(content, filename string) (*os.File, error) {
	// 获取系统临时目录
	tempDir := os.TempDir()
	// 构建完整路径
	filePath := filepath.Join(tempDir, filename)

	// 检查文件是否已存在，存在则删除（避免冲突）
	if _, err := os.Stat(filePath); err == nil {
		if err := os.Remove(filePath); err != nil {
			return nil, err
		}
	}

	// 创建文件
	file, err := os.Create(filePath)
	if err != nil {
		return nil, err
	}

	// 写入内容
	if _, err := file.WriteString(content); err != nil {
		file.Close()
		os.Remove(filePath)
		return nil, err
	}

	// 关闭后重新以只读方式打开
	file.Close()
	return os.Open(filePath)
}

// 上传多个文件并发送参数
func uploadMultipleFilesAndParams(qhurl string, files []FileInfo, params map[string]string, header map[string]string) ([]byte, error) {

	// 创建一个缓冲区用于存储 multipart/form-data 数据
	var requestBody bytes.Buffer
	writer := multipart.NewWriter(&requestBody)

	// 添加普通参数
	for key, value := range params {
		if err := writer.WriteField(key, value); err != nil {
			return nil, fmt.Errorf("添加参数 %s 失败: %v", key, err)
		}
	}

	// 循环添加多个文件，以二进制方式处理
	for _, fileInfo := range files {
		// 以只读和二进制模式打开文件
		file, err := os.OpenFile(fileInfo.FilePath, os.O_RDONLY, 0644)
		if err != nil {
			return nil, fmt.Errorf("打开文件 %s 失败: %v", fileInfo.FilePath, err)
		}
		// defer在当前函数（processFile）结束时执行，而非循环结束
		defer func() {
			if err := file.Close(); err != nil {
				//fmt.Printf("关闭文件 %s 时出错: %v\n", fileInfo.FilePath, err)
			}
		}()
		// 获取文件信息
		//_, err = file.Stat()
		//if err != nil {
		//	return nil, fmt.Errorf("获取文件 %s 信息失败: %v", fileInfo.FilePath, err)
		//}
		//fmt.Printf("准备上传文件: %s (大小: %d 字节, key: %s)\n",
		//	fileInfo.FilePath, fileStat.Size(), fileInfo.Key)

		// 使用自定义的key创建表单文件字段
		part, err := writer.CreateFormFile(fileInfo.Key, filepath.Base(fileInfo.FilePath))
		if err != nil {
			return nil, fmt.Errorf("为文件 %s 创建表单字段（key: %s）失败: %v",
				fileInfo.FilePath, fileInfo.Key, err)
		}

		// 以二进制方式将文件内容复制到表单字段
		// 使用io.Copy直接复制二进制数据，不做任何文本转换
		_, err = io.Copy(part, file)
		if err != nil {
			return nil, fmt.Errorf("复制文件 %s 内容失败: %v", fileInfo.FilePath, err)
		}

		//fmt.Printf("已上传文件: %s (已写入 %d 字节)\n", fileInfo.FilePath, bytesWritten)
	}

	// 关闭 multipart writer，完成表单构建
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("关闭 writer 失败: %v", err)
	}

	// 创建 HTTP 请求
	req, err := http.NewRequest("POST", qhurl, &requestBody)
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %v", err)
	}
	// 添加header
	for key, value := range header {
		req.Header.Set(key, value)
	}
	// 设置 Content-Type 头
	req.Header.Set("Content-Type", writer.FormDataContentType())
	// 设置User-Agent，模拟浏览器行为
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:    10,
			MaxConnsPerHost: 10,
			IdleConnTimeout: 30 * time.Second,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // 忽略证书验证
			},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("发送请求失败: %v", err)
	}
	defer resp.Body.Close()

	// 读取响应内容
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %v", err)
	}

	// 检查响应状态码
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("请求失败，状态码: %d, 响应内容: %s", resp.StatusCode, string(respBody))
	}

	//return string(respBody), nil
	return respBody, nil
}

// 检查并找出重复的commonName
func FindDuplicateCommonNames(certificates []Certificate, commonName string) *Certificate {
	for i, cert := range certificates {
		if cert.Subject.CommonName == commonName {
			return &certificates[i]
		}
	}
	return nil
}
