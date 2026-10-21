package main

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/beevik/etree"
)

var b64 = base64.RawURLEncoding.EncodeToString

func encodeB64Std(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// ---- JWT ----

func signJWT(key *rsa.PrivateKey, header, claims map[string]any) string {
	hb, _ := json.Marshal(header)
	cb, _ := json.Marshal(claims)
	in := b64(hb) + "." + b64(cb)
	if header["alg"] == "none" {
		return in + "."
	}
	sum := sha256.Sum256([]byte(in))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	return in + "." + b64(sig)
}

func decodeJWT(tok string) (header, claims map[string]any, err error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return nil, nil, errors.New("not a JWT: want 3 dot-separated parts")
	}
	for i, dst := range []*map[string]any{&header, &claims} {
		b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[i], "="))
		if err != nil {
			return nil, nil, fmt.Errorf("part %d: %w", i+1, err)
		}
		if err := json.Unmarshal(b, dst); err != nil {
			return nil, nil, fmt.Errorf("part %d: %w", i+1, err)
		}
	}
	return header, claims, nil
}

func verifyJWT(tok string, pub *rsa.PublicKey) error {
	i := strings.LastIndex(tok, ".")
	if i < 0 {
		return errors.New("not a JWT")
	}
	sig, err := base64.RawURLEncoding.DecodeString(tok[i+1:])
	if err != nil || len(sig) == 0 {
		return errors.New("no signature")
	}
	sum := sha256.Sum256([]byte(tok[:i]))
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig)
}

func atHash(accessToken string) string {
	sum := sha256.Sum256([]byte(accessToken))
	return b64(sum[:16])
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func num(v any) int64 {
	switch n := v.(type) {
	case float64:
		return int64(n)
	case int64:
		return n
	case int:
		return int64(n)
	}
	return 0
}

// ---- SAML messages ----

// decodeSAMLMessage undoes base64 and, when present, the DEFLATE of the
// HTTP-Redirect binding. It forgives the usual damage done to base64 in
// query strings.
func decodeSAMLMessage(raw string) (string, error) {
	raw = strings.ReplaceAll(raw, " ", "+")
	raw = strings.NewReplacer("\n", "", "\r", "", "\t", "").Replace(raw)
	b, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		if b, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(raw, "=")); err != nil {
			return "", fmt.Errorf("not base64: %w", err)
		}
	}
	if out, err := io.ReadAll(flate.NewReader(bytes.NewReader(b))); err == nil && len(out) > 0 {
		return string(out), nil
	}
	return string(b), nil
}

func deflateB64(s string) string {
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.DefaultCompression)
	w.Write([]byte(s))
	w.Close()
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

func prettyXML(s string) string {
	doc := etree.NewDocument()
	if err := doc.ReadFromString(s); err != nil {
		return s
	}
	doc.Indent(2)
	out, _ := doc.WriteToString()
	return out
}

func child(el *etree.Element, tag string) *etree.Element {
	for _, c := range el.ChildElements() {
		if c.Tag == tag {
			return c
		}
	}
	return nil
}

func children(el *etree.Element, tag string) []*etree.Element {
	var out []*etree.Element
	for _, c := range el.ChildElements() {
		if c.Tag == tag {
			out = append(out, c)
		}
	}
	return out
}

// find is a depth-first search by local name, ignoring namespace prefixes.
func find(el *etree.Element, tag string) *etree.Element {
	for _, c := range el.ChildElements() {
		if c.Tag == tag {
			return c
		}
		if f := find(c, tag); f != nil {
			return f
		}
	}
	return nil
}

func text(el *etree.Element) string {
	if el == nil {
		return ""
	}
	return strings.TrimSpace(el.Text())
}

// ---- decoder for the dashboard and API ----

func decodeAny(in string) map[string]any {
	in = strings.TrimSpace(in)
	if u, err := url.Parse(in); err == nil && u.Scheme != "" && u.Host != "" && (u.RawQuery != "" || u.Fragment != "") {
		vals := u.Query()
		if frag, err := url.ParseQuery(u.Fragment); err == nil {
			for k, v := range frag {
				vals[k] = v
			}
		}
		params := map[string]string{}
		out := map[string]any{"type": "url", "params": params}
		for k := range vals {
			params[k] = vals.Get(k)
			switch k {
			case "SAMLRequest", "SAMLResponse", "id_token", "access_token", "logout_token":
				out[k] = decodeAny(vals.Get(k))
			}
		}
		return out
	}
	if strings.Count(in, ".") == 2 && !strings.ContainsAny(in, " <") {
		if h, c, err := decodeJWT(in); err == nil {
			return map[string]any{"type": "jwt", "header": h, "claims": c, "times": jwtTimes(c)}
		}
	}
	if strings.HasPrefix(in, "<") {
		return map[string]any{"type": "xml", "xml": prettyXML(in)}
	}
	if s, err := decodeSAMLMessage(in); err == nil && strings.HasPrefix(strings.TrimSpace(s), "<") {
		return map[string]any{"type": "saml", "xml": prettyXML(s)}
	}
	return map[string]any{"type": "unknown", "error": "Not a JWT, a SAML message, XML, or a URL carrying one of those."}
}

func jwtTimes(c map[string]any) map[string]string {
	out := map[string]string{}
	for _, k := range []string{"iat", "nbf", "exp", "auth_time"} {
		if n := num(c[k]); n > 0 {
			t := time.Unix(n, 0).UTC()
			rel := time.Until(t).Round(time.Second)
			when := "in " + rel.String()
			if rel < 0 {
				when = (-rel).String() + " ago"
			}
			out[k] = t.Format(time.RFC3339) + " (" + when + ")"
		}
	}
	return out
}

func prettyJSON(v any) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}
