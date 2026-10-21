package main

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/beevik/etree"
)

// XML Encryption for SAML assertions (W3C xmlenc-core and xmlenc-core1), and
// verification of signed AuthnRequests.

const (
	xencNS   = "http://www.w3.org/2001/04/xmlenc#"
	xenc11NS = "http://www.w3.org/2009/xmlenc11#"
	dsNS     = "http://www.w3.org/2000/09/xmldsig#"
)

var blockAlgs = map[string]string{
	"aes128-cbc": xencNS + "aes128-cbc",
	"aes256-cbc": xencNS + "aes256-cbc",
	"aes128-gcm": xenc11NS + "aes128-gcm",
	"aes256-gcm": xenc11NS + "aes256-gcm",
}

var keyTransportAlgs = map[string]string{
	"rsa-oaep": xencNS + "rsa-oaep-mgf1p",
	"rsa-1_5":  xencNS + "rsa-1_5",
}

// parseSPCert reads an SP certificate given as PEM, bare base64 DER, or the
// SP's metadata XML, in which case the KeyDescriptor for `use` is taken (or
// one with no use, which covers both).
func parseSPCert(s, use string) (*x509.Certificate, error) {
	s = strings.TrimSpace(s)
	switch {
	case s == "":
		return nil, errors.New("no certificate given")
	case strings.HasPrefix(s, "<"):
		doc := etree.NewDocument()
		if err := doc.ReadFromString(s); err != nil {
			return nil, fmt.Errorf("metadata is not XML: %w", err)
		}
		var any string
		for _, kd := range doc.FindElements("//KeyDescriptor") {
			c := text(find(kd, "X509Certificate"))
			switch kd.SelectAttrValue("use", "") {
			case use:
				return parseSPCert(c, use)
			case "":
				any = c
			}
		}
		if any == "" {
			return nil, fmt.Errorf("metadata has no %s certificate", use)
		}
		return parseSPCert(any, use)
	case strings.HasPrefix(s, "-----BEGIN"):
		b, _ := pem.Decode([]byte(s))
		if b == nil {
			return nil, errors.New("bad PEM")
		}
		return x509.ParseCertificate(b.Bytes)
	}
	der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(s), ""))
	if err != nil {
		return nil, errors.New("not PEM, base64 or metadata XML")
	}
	return x509.ParseCertificate(der)
}

func sameCert(a, b string) bool {
	ca, err1 := parseSPCert(a, "signing")
	cb, err2 := parseSPCert(b, "signing")
	return err1 == nil && err2 == nil && ca.Equal(cb)
}

// encryptAssertion seals a (usually already signed) assertion for the SP and
// returns the saml:EncryptedAssertion that replaces it.
func encryptAssertion(as *etree.Element, cert *x509.Certificate, alg, transport string) (*etree.Element, error) {
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("the SP encryption certificate must hold an RSA key")
	}
	if alg == "" {
		alg = "aes256-cbc"
	}
	if transport == "" {
		transport = "rsa-oaep"
	}
	if blockAlgs[alg] == "" || keyTransportAlgs[transport] == "" {
		return nil, fmt.Errorf("unknown encryption algorithm %s / %s", alg, transport)
	}
	doc := etree.NewDocument()
	doc.SetRoot(as.Copy())
	plain, err := doc.WriteToBytes()
	if err != nil {
		return nil, err
	}

	key := make([]byte, 32)
	if strings.HasPrefix(alg, "aes128") {
		key = key[:16]
	}
	rand.Read(key)
	block, _ := aes.NewCipher(key)
	var sealed []byte
	if strings.HasSuffix(alg, "gcm") {
		g, _ := cipher.NewGCM(block)
		iv := make([]byte, g.NonceSize())
		rand.Read(iv)
		sealed = append(iv, g.Seal(nil, iv, plain, nil)...)
	} else {
		// xmlenc padding: the last byte says how many bytes were added.
		n := aes.BlockSize - len(plain)%aes.BlockSize
		padded := append(plain, make([]byte, n)...)
		for i := len(plain); i < len(padded); i++ {
			padded[i] = byte(n)
		}
		iv := make([]byte, aes.BlockSize)
		rand.Read(iv)
		out := make([]byte, len(padded))
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, padded)
		sealed = append(iv, out...)
	}

	var wrapped []byte
	if transport == "rsa-1_5" {
		wrapped, err = rsa.EncryptPKCS1v15(rand.Reader, pub, key)
	} else {
		wrapped, err = rsa.EncryptOAEP(sha1.New(), rand.Reader, pub, key, nil)
	}
	if err != nil {
		return nil, err
	}

	b64s := base64.StdEncoding.EncodeToString
	ea := etree.NewElement("saml:EncryptedAssertion")
	ea.CreateAttr("xmlns:saml", nsAssertion)
	ed := ea.CreateElement("xenc:EncryptedData")
	ed.CreateAttr("xmlns:xenc", xencNS)
	ed.CreateAttr("Type", xencNS+"Element")
	ed.CreateElement("xenc:EncryptionMethod").CreateAttr("Algorithm", blockAlgs[alg])
	ki := ed.CreateElement("ds:KeyInfo")
	ki.CreateAttr("xmlns:ds", dsNS)
	ek := ki.CreateElement("xenc:EncryptedKey")
	em := ek.CreateElement("xenc:EncryptionMethod")
	em.CreateAttr("Algorithm", keyTransportAlgs[transport])
	if transport == "rsa-oaep" {
		em.CreateElement("ds:DigestMethod").CreateAttr("Algorithm", dsNS+"sha1")
	}
	ek.CreateElement("ds:KeyInfo").CreateElement("ds:X509Data").CreateElement("ds:X509Certificate").SetText(b64s(cert.Raw))
	ek.CreateElement("xenc:CipherData").CreateElement("xenc:CipherValue").SetText(b64s(wrapped))
	ed.CreateElement("xenc:CipherData").CreateElement("xenc:CipherValue").SetText(b64s(sealed))
	return ea, nil
}

// decryptAssertion opens a saml:EncryptedAssertion with the SP's key. It
// returns the assertion and a short description of the algorithms used.
func decryptAssertion(ea *etree.Element, key *rsa.PrivateKey) (*etree.Element, string, error) {
	ed := child(ea, "EncryptedData")
	if ed == nil {
		return nil, "", errors.New("no EncryptedData")
	}
	ek := find(ed, "EncryptedKey")
	if ek == nil || child(ed, "EncryptionMethod") == nil || child(ek, "EncryptionMethod") == nil {
		return nil, "", errors.New("EncryptedData is missing its EncryptionMethod or EncryptedKey")
	}
	alg := child(ed, "EncryptionMethod").SelectAttrValue("Algorithm", "")
	transport := child(ek, "EncryptionMethod").SelectAttrValue("Algorithm", "")
	unb64 := func(el *etree.Element) []byte {
		b, _ := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(text(el)), ""))
		return b
	}
	wrapped := unb64(find(child(ek, "CipherData"), "CipherValue"))
	sealed := unb64(find(child(ed, "CipherData"), "CipherValue"))
	short := func(uri string) string { return uri[strings.LastIndex(uri, "#")+1:] }
	desc := short(alg) + " + " + short(transport)

	var symKey []byte
	var err error
	switch transport {
	case keyTransportAlgs["rsa-oaep"]:
		symKey, err = rsa.DecryptOAEP(sha1.New(), nil, key, wrapped, nil)
	case keyTransportAlgs["rsa-1_5"]:
		symKey, err = rsa.DecryptPKCS1v15(nil, key, wrapped)
	default:
		return nil, desc, fmt.Errorf("unsupported key transport %s", transport)
	}
	if err != nil {
		return nil, desc, fmt.Errorf("cannot unwrap the key: it was encrypted for another certificate (%v)", err)
	}
	block, err := aes.NewCipher(symKey)
	if err != nil {
		return nil, desc, err
	}
	var plain []byte
	switch {
	case strings.HasSuffix(alg, "gcm"):
		g, _ := cipher.NewGCM(block)
		if len(sealed) < g.NonceSize() {
			return nil, desc, errors.New("ciphertext too short")
		}
		if plain, err = g.Open(nil, sealed[:g.NonceSize()], sealed[g.NonceSize():], nil); err != nil {
			return nil, desc, errors.New("GCM authentication failed: the ciphertext was changed")
		}
	case strings.HasSuffix(alg, "cbc"):
		if len(sealed) < 2*aes.BlockSize || len(sealed)%aes.BlockSize != 0 {
			return nil, desc, errors.New("bad CBC ciphertext length")
		}
		plain = make([]byte, len(sealed)-aes.BlockSize)
		cipher.NewCBCDecrypter(block, sealed[:aes.BlockSize]).CryptBlocks(plain, sealed[aes.BlockSize:])
		n := int(plain[len(plain)-1])
		if n < 1 || n > aes.BlockSize {
			return nil, desc, errors.New("bad padding")
		}
		plain = plain[:len(plain)-n]
	default:
		return nil, desc, fmt.Errorf("unsupported block cipher %s", alg)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(plain); err != nil || doc.Root() == nil {
		return nil, desc, errors.New("decrypted data is not XML")
	}
	return doc.Root(), desc, nil
}

var sigAlgHashes = map[string]crypto.Hash{
	"http://www.w3.org/2000/09/xmldsig#rsa-sha1":        crypto.SHA1,
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256": crypto.SHA256,
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha512": crypto.SHA512,
}

// verifyRedirectSignature checks an HTTP-Redirect binding signature. The
// signed bytes are the parameters exactly as they arrived, still URL-encoded,
// in the fixed order the binding defines (SAML bindings §3.4.4.1).
func verifyRedirectSignature(rawQuery string, cert *x509.Certificate) (sigAlg string, err error) {
	raw := map[string]string{}
	for _, kv := range strings.Split(rawQuery, "&") {
		if k, v, ok := strings.Cut(kv, "="); ok {
			raw[k] = v
		}
	}
	msg := "SAMLRequest"
	if raw[msg] == "" {
		msg = "SAMLResponse"
	}
	signed := msg + "=" + raw[msg]
	if v, ok := raw["RelayState"]; ok {
		signed += "&RelayState=" + v
	}
	signed += "&SigAlg=" + raw["SigAlg"]
	sigAlg, _ = url.QueryUnescape(raw["SigAlg"])
	h, ok := sigAlgHashes[sigAlg]
	if !ok {
		return sigAlg, fmt.Errorf("unsupported SigAlg %q", sigAlg)
	}
	sigB64, _ := url.QueryUnescape(raw["Signature"])
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return sigAlg, errors.New("Signature is not base64")
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return sigAlg, errors.New("the SP signing certificate must hold an RSA key")
	}
	var sum []byte
	switch h {
	case crypto.SHA1:
		s := sha1.Sum([]byte(signed))
		sum = s[:]
	case crypto.SHA256:
		s := sha256.Sum256([]byte(signed))
		sum = s[:]
	default:
		s := sha512.Sum512([]byte(signed))
		sum = s[:]
	}
	if err := rsa.VerifyPKCS1v15(pub, h, sum, sig); err != nil {
		return sigAlg, errors.New("signature does not match the SP signing certificate")
	}
	return sigAlg, nil
}

// signRedirect signs an HTTP-Redirect query with RSA-SHA256. q already holds
// the URL-encoded message and RelayState.
func signRedirect(q string, key *rsa.PrivateKey) string {
	q += "&SigAlg=" + url.QueryEscape("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
	sum := sha256.Sum256([]byte(q))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	return q + "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sig))
}
