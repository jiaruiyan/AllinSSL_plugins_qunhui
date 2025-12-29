package main

import (
	"ALLinSSL/plugins/qunhui/lib"
	"fmt"
	"strconv"
)

func deploy(cfg map[string]any) (*Response, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}
	certPEM, ok := cfg["cert"].(string)
	if !ok || certPEM == "" {
		return nil, fmt.Errorf("cert is required and must be a string")
	}
	privkeyPEM, ok := cfg["key"].(string)
	if !ok || privkeyPEM == "" {
		return nil, fmt.Errorf("key is required and must be a string")
	}
	synoUsername, ok := cfg["SYNO_USERNAME"].(string)
	if !ok || synoUsername == "" {
		return nil, fmt.Errorf("SYNO_USERNAME is required and must be a string")
	}
	synoPassword, ok := cfg["SYNO_PASSWORD"].(string)
	if !ok || synoPassword == "" {
		return nil, fmt.Errorf("SYNO_PASSWORD is required and must be a string")
	}
	synoScheme, ok := cfg["SYNO_SCHEME"].(string)
	if !ok || synoScheme == "" {
		return nil, fmt.Errorf("SYNO_SCHEME is required and must be a string")
	}

	var synoPort int64
	switch v := cfg["SYNO_PORT"].(type) {
	case float64:
		synoPort = int64(v)
		break
	case string:
		var err error
		synoPort, err = strconv.ParseInt(v, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("SYNO_PORT format error: %w", err)
		}
		break
	case int:
		synoPort = int64(v)
		break
	default:
		return nil, fmt.Errorf("SYNO_PORT format error")
	}
	synoHostname, ok := cfg["SYNO_HOSTNAME"].(string)
	if !ok || synoHostname == "" {
		return nil, fmt.Errorf("SYNO_HOSTNAME is required and must be a string")
	}

	var asDefault bool
	switch v := cfg["AS_DEFAULT"].(type) {
	case string:
		if v == "true" {
			asDefault = true
		} else {
			asDefault = false
		}
		break
	case bool:
		asDefault = v
		break
	default:
		return nil, fmt.Errorf("AS_DEFAULT is required and must be a bool")
	}
	// 解析现有证书的域名
	certObj, err := ParseCertificate([]byte(certPEM))
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}
	client := lib.Client{
		Scheme:   "http",
		Host:     synoHostname,
		Port:     synoPort,
		UserName: synoUsername,
		Password: synoPassword,
	}
	err = client.Login()
	if err != nil {
		return nil, err
	}
	certList, err := client.CrtList()
	if err != nil {
		return nil, err
	}
	certInfo := lib.FindDuplicateCommonNames(certList.Data.Certificates, certObj.Subject.CommonName)
	var certId string
	if certInfo == nil {
		certId = ""
	} else {
		certId = certInfo.ID
	}

	err = client.Certificate(privkeyPEM, certPEM, certId, asDefault)
	if err != nil {
		return nil, err
	}
	return &Response{
		Status:  "success",
		Message: "The certificate deployment was successful.",
		Result:  nil,
	}, nil

}
