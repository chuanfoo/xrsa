# xrsa

### 功能

- 加密解密不限长度的数据
- 创建pkcs8格式私钥

### 创建公钥私钥

```
pubKey, priKey := CreateKeys(1024)
fmt.Println(pubKey)
fmt.Println(priKey)
```

### 初始化

```
// 公钥
PUB = ""
// 私钥
PRV = ""
myrsa, err = NewXRsa(PUB, PRV)
if err != nil {
    panic(err)
}
```

### 公钥加密

```
rawData := "hello"
eData, err := myrsa.PublicEncrypt(rawData)
if err != nil {
	fmt.Println(err)
}
```

### 私钥解密

```
dData, err := myrsa.PrivateDecrypt(eData)
if err != nil {
	fmt.Println(err)
}
fmt.Println(dData)
```