// Copyright 2021 The tool Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"
)

const (
	AesKey               = "#HvL%$o0oNNoOZnk#o2qbqCeQB1iXeIR" // 对称秘钥长度必须是16的倍数
	ClientiniTemplate    = "Pa6FhEtM8mOoprOuS82gu5kkjEZErpajtAGuNAmog+b5LIg5Sf3x3oDEKNIheBVZ3Gm9Ih8uOkQX8VgNvcv5X91cyFzq6kNVgQQ12mV5DbydHeoDRAYUisjmKRZQNsc2oCGYzoU+6qfupzmW6mVT0RRS5N7Jq7GD9JbkU9HYZd8mOUV6vr6PaK0MW+5/UTsjlUyUMe4dZnuQb1syRpGTApwfRN226/uyZs8i9LEbKAA/RH/bJFpgVQT23DPmxpgkzBC+XVHn8CwromTFyje7ZeeLXaWNc6Z4omEfzQ1F6ODuXw6d9pb1S+YeSxylJ2Qu/ijCydvpmGN0w91G0EgkJTS9TNyf1r6K3DyqBHyhslo="
	ClientiniTemplateKcp = "Pa6FhEtM8mOoprOuS82gu5kkjEZErpajtAGuNAmog+aexsEWyovlueUakIvarzIpUnkB2+hPN6FGSIgyk/eN/O1DNBTs+bUFZpN2N5f265H6Iwo7ZyM4UYoKjVlOckn4Y5HlvAhHPn9jXQKOCKBmRRm2NY5LIDEWDc8TT/BXz8eXDeVYkycaQLK/rOoIDXouCtTCz5rEg5Hv1p3A0PTMq7qO/1EAPBwvShEv+lIKqhT2Cphv8AyU/eONRtrUzdYPBxORkaTVG/qq0wfD9b2Gp9PIh5AHm/GBkY45rEqELhCWVGpU+DtNwk79Im9HRq/zpADF84mcrHKLnfHApC5urzbI3jXm0t7BLgy/Gb0Kp7Y="
)

func bytes2str(b []byte) string {
	return *(*string)(unsafe.Pointer(&b))
}

func Str2bytes(s string) []byte {
	x := (*[2]uintptr)(unsafe.Pointer(&s))
	h := [3]uintptr{x[0], x[1], x[1]}
	return *(*[]byte)(unsafe.Pointer(&h))
}

// Aes加密
func AesEncrypt(data []byte, key []byte) ([]byte, error) {
	//创建加密实例
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	//判断加密快的大小
	blockSize := block.BlockSize()
	//填充
	encryptBytes := pkcs7Padding(data, blockSize)
	//初始化加密数据接收切片
	crypted := make([]byte, len(encryptBytes))
	//使用cbc加密模式
	blockMode := cipher.NewCBCEncrypter(block, key[:blockSize])
	//执行加密
	blockMode.CryptBlocks(crypted, encryptBytes)
	return crypted, nil
}

// AES解密
func AesDecrypt(crypted, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])
	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, crypted)
	origData = PKCS7UnPadding(origData)
	return origData, nil
}

// pkcs7Padding 填充
func pkcs7Padding(data []byte, blockSize int) []byte {
	//判断缺少几位长度。最少1，最多 blockSize
	padding := blockSize - len(data)%blockSize
	//补足位数。把切片[]byte{byte(padding)}复制padding个
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

func PKCS7UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func DecryptAesConfig(aesStr string, aeskey []byte) [5]string {
	if len(aesStr) < 10 {
		os.Exit(1)
	}

	encrypteds2, _ := base64.StdEncoding.DecodeString(aesStr)
	var encrypted2 = encrypteds2
	text, err := AesDecrypt(encrypted2, aeskey)

	//type, host, port, name, bind_port
	var configArray [5]string

	if err != nil {
		// panic(err)
		os.Exit(1)
	}

	countSplit := strings.Split(bytes2str(text), ":")
	configArray[0] = countSplit[0]
	configArray[1] = countSplit[1]
	configArray[2] = countSplit[2]
	configArray[3] = countSplit[3]

	length := len(countSplit)
	if length == 5 {
		configArray[4] = countSplit[4]
	} else {
		configArray[4] = "443"
	}
	//fmt.Println(configArray)
	return configArray
}

func ParseClientConfig(configarray [5]string) (
	cfg ClientCommonConf,
	pxyCfgs map[string]ProxyConf,
	visitorCfgs map[string]VisitorConf,
	err error,
) {

	var ClientTemplate string
	//change
	//mode:UDP
	//fmt.Println("mode:" + configarray[0])
	if configarray[0] == "U" {
		//use kcp
		ClientTemplate = ClientiniTemplateKcp
	} else {
		ClientTemplate = ClientiniTemplate
	}

	encrypteds, _ := base64.StdEncoding.DecodeString(ClientTemplate)
	content, err := AesDecrypt(encrypteds, Str2bytes(AesKey))
	if err != nil {
		panic(err)
	}

	var str string
	str = bytes2str(content)
	str = strings.Replace(str, "plugin_socks", configarray[3], -1)
	str = strings.Replace(str, "server_addr = xxx", "server_addr = "+configarray[1], -1)
	str = strings.Replace(str, "remote_port = xxx", "remote_port = "+configarray[2], -1)
	str = strings.Replace(str, "server_port = 443", "server_port = "+configarray[4], -1)
	str = strings.Replace(str, "plugin_user = xxx", "plugin_user = "+configarray[3], -1)
	str = strings.Replace(str, "plugin_passwd = xxx", "plugin_passwd = "+configarray[3]+"#8848", -1)

	content = Str2bytes(str)

	//var content []byte
	//content, err = GetRenderedConfFromFile(filePath)
	//if err != nil {
	//	return
	//}

	configBuffer := bytes.NewBuffer(nil)
	configBuffer.Write(content)

	// Parse common section.
	cfg, err = UnmarshalClientConfFromIni(content)
	if err != nil {
		return
	}
	cfg.Complete()
	if err = cfg.Validate(); err != nil {
		err = fmt.Errorf("parse config error: %v", err)
		return
	}

	// Aggregate proxy configs from include files.
	var buf []byte
	buf, err = getIncludeContents(cfg.IncludeConfigFiles)
	if err != nil {
		err = fmt.Errorf("getIncludeContents error: %v", err)
		return
	}
	configBuffer.WriteString("\n")
	configBuffer.Write(buf)

	// Parse all proxy and visitor configs.
	pxyCfgs, visitorCfgs, err = LoadAllProxyConfsFromIni(cfg.User, configBuffer.Bytes(), cfg.Start)
	if err != nil {
		return
	}
	return
}

// getIncludeContents renders all configs from paths.
// files format can be a single file path or directory or regex path.
func getIncludeContents(paths []string) ([]byte, error) {
	out := bytes.NewBuffer(nil)
	for _, path := range paths {
		absDir, err := filepath.Abs(filepath.Dir(path))
		if err != nil {
			return nil, err
		}
		if _, err := os.Stat(absDir); os.IsNotExist(err) {
			return nil, err
		}
		files, err := os.ReadDir(absDir)
		if err != nil {
			return nil, err
		}
		for _, fi := range files {
			if fi.IsDir() {
				continue
			}
			absFile := filepath.Join(absDir, fi.Name())
			if matched, _ := filepath.Match(filepath.Join(absDir, filepath.Base(path)), absFile); matched {
				tmpContent, err := GetRenderedConfFromFile(absFile)
				if err != nil {
					return nil, fmt.Errorf("render extra config %s error: %v", absFile, err)
				}
				out.Write(tmpContent)
				out.WriteString("\n")
			}
		}
	}
	return out.Bytes(), nil
}
