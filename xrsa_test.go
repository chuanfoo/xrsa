package xrsa

import (
	"fmt"
	"testing"
)

var (
	// 公钥
	PUB = "-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDQ/1tPCk+L++PGHU58XtHbo5PZ\n9IKKOifu5Kb/h328ougVxX6q3cvojbbeRgywVVTCSpgVFBU6BWLTOii5XNgViYzl\nYsBWvb34gyxgcj9AmUMdSuYhaborWnet0fUsKdU1jlFKyIazKj3WrQNIf5Pf4UdV\nBh/qu/Dz4RBltV5pTQIDAQAB\n-----END PUBLIC KEY-----"
	// 私钥
	PRV   = "-----BEGIN PRIVATE KEY-----\nMIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAND/W08KT4v748Yd\nTnxe0dujk9n0goo6J+7kpv+Hfbyi6BXFfqrdy+iNtt5GDLBVVMJKmBUUFToFYtM6\nKLlc2BWJjOViwFa9vfiDLGByP0CZQx1K5iFpuitad63R9Swp1TWOUUrIhrMqPdat\nA0h/k9/hR1UGH+q78PPhEGW1XmlNAgMBAAECgYAlNZF4HQnUjmAbIZSbp/YM+K6W\nG2YyXfBGJAdnbyP/tbFETwkiOqLXIIPyRt5zdn3Eqasx9YVh8xuJJ82gUttVh+mU\nu9c+bHrTxlbyANC3CcOUmukq08UMZ+0RQgDQOlfNrRJ+0HdaGVZtyRyxHSIAa6Z9\n6wIubX+obex6b88/sQJBAOJRkxDzbrH6sPSYapD/nxAYi6dy9mFQbvW2Z0hUvPo9\nzms+db/mFXX5sLvyMxeEFPn+JwsiomvhyF8pf+l9CVsCQQDsaD3Ajkhp/bkYN0bj\njvhz9VVhJrCVzKOfnE1QzLRyumtUkTYIZ4PMpvyduhAwQ80PrhIgjJC5EFs3BYS5\n2jB3AkEAuQ/naFcGz3alOH1htsuv7+OCXxy8p3q0ISxUbGsOVLoxjrR2aMLmDaBt\nimJUsQgKdxoCJzLdCcaIqHgw5maePQJAOo5jZVOY2jAPbdEbTPg30Dkfac30hVZH\n3RwRBod91sEYHr1NHe3N9p4SCltw8ROKMm0Sbl+C5WQIw+spAgPqZwJAJrqzQC98\n3Z7MdciIunEvwKD6QSe3XXCq1KzJDRaXrjUOKMHpmhc3tED/DxnRk+5ow0NmArBc\nc3QGLm9lmesgxQ==\n-----END PRIVATE KEY-----"
	myrsa *XRsa
	// 待加密数据
	rawData = "hello"
)

func init() {
	myrsa, _ = NewXRsa(PUB, PRV)
}

func TestCreateKeys(t *testing.T) {
	pubKey, priKey := CreateKeys(1024)
	fmt.Println(pubKey)
	fmt.Println(priKey)
}

// 公钥加密 私钥解密
func TestXRsa_PublicEncrypt(t *testing.T) {
	eData, err := myrsa.PublicEncrypt(rawData)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(eData)
	dData, _ := myrsa.PrivateDecrypt(eData)
	if rawData != dData {
		t.Errorf("解密失败")
	}
}
