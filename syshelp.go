package zhouess

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"encoding/base64"
)

// SCEncryptString SCEncryptString
func SCEncryptString(originalText, key, scType string) (string, error) {
	chipherArr, err := encrypt([]byte(originalText), []byte(key), scType)
	if err != nil {
		panic(err)
	}
	base64str := base64.StdEncoding.EncodeToString(chipherArr)
	return base64str, nil
}

// SCDecryptString SCDecryptString
func SCDecryptString(chipherText, key, scType string) (string, error) {
	chipherArr, _ := base64.StdEncoding.DecodeString(chipherText)
	chipherArr, err := decrypt(chipherArr, []byte(key), scType)
	if err != nil {
		panic(err)
	}
	return string(chipherArr), nil
}

// SCEncrypt DES加密
func encrypt(originalBytes, key []byte, scType string) ([]byte, error) {
	// 1、实例化密码器block(参数为密钥)
	var err error
	var block cipher.Block
	switch scType {
	case "des":
		block, err = des.NewCipher(key)
	case "3des":
		block, err = des.NewTripleDESCipher(key)
	case "aes":
		block, err = aes.NewCipher(key)
	}
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	//fmt.Println("---blockSize---", blockSize)
	// 2、对明文填充字节(参数为原始字节切片和密码对象的区块个数)
	paddingBytes := pkcssPadding(originalBytes, blockSize)
	//fmt.Println("填充后的字节切片：", paddingBytes)
	// 3、 实例化加密模式(参数为密码对象和密钥)
	blockMode := cipher.NewCBCEncrypter(block, key[:blockSize])
	//fmt.Println("加密模式：", blockMode)
	// 4、对填充字节后的明文进行加密(参数为加密字节切片和填充字节切片)
	cipherBytes := make([]byte, len(paddingBytes))
	blockMode.CryptBlocks(cipherBytes, paddingBytes)
	return cipherBytes, nil
}

// SCDecrypt 解密字节切片，返回字节切片
func decrypt(cipherBytes, key []byte, scType string) ([]byte, error) {
	// 1、实例化密码器block(参数为密钥)
	var err error
	var block cipher.Block
	switch scType {
	case "des":
		block, err = des.NewCipher(key)
	case "3des":
		block, err = des.NewTripleDESCipher(key)
	case "aes":
		block, err = aes.NewCipher(key)
	}
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	// 2、 实例化解密模式(参数为密码对象和密钥)
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])
	// fmt.Println("解密模式：", blockMode)
	// 3、对密文进行解密(参数为加密字节切片和填充字节切片)
	paddingBytes := make([]byte, len(cipherBytes))
	blockMode.CryptBlocks(paddingBytes, cipherBytes)
	// 4、去除填充字节(参数为填充切片)
	originalBytes := pkcssUnPadding(paddingBytes)
	return originalBytes, nil
}

// PKCSSPadding 填充字节的函数
func pkcssPadding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	//fmt.Println("要填充的字节：", padding)
	// 初始化一个元素为padding的切片
	slice1 := []byte{byte(padding)}
	slice2 := bytes.Repeat(slice1, padding)
	return append(data, slice2...)
}

// ZeroPadding 填充字节的函数
func zeroPadding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	//fmt.Println("要填充的字节：", padding)
	// 初始化一个元素为padding的切片
	slice1 := []byte{0}
	slice2 := bytes.Repeat(slice1, padding)
	return append(data, slice2...)
}

// PKCSSUnPadding 去除填充字节的函数
func pkcssUnPadding(data []byte) []byte {
	unpadding := data[len(data)-1]
	result := data[:(len(data) - int(unpadding))]
	return result
}

// ZeroUnPadding 去除填充字节的函数
func zeroUnPadding(data []byte) []byte {
	return bytes.TrimRightFunc(data, func(r rune) bool {
		return r == 0
	})
}
