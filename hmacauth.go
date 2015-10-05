package hmacauth

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"strings"
)

type HmacAuth interface {
	StringToSign(req *http.Request) string
	SignRequest(req *http.Request)
	RequestSignature(req *http.Request) string
	SignatureFromHeader(req *http.Request) string
	ValidateRequest(request *http.Request) (
		result ValidationResult,
		headerSignature, computedSignature string)
}

var supportedAlgorithms map[string]crypto.Hash = map[string]crypto.Hash{
	"md4":       crypto.MD4,
	"md5":       crypto.MD5,
	"sha1":      crypto.SHA1,
	"sha224":    crypto.SHA224,
	"sha256":    crypto.SHA256,
	"sha384":    crypto.SHA384,
	"sha512":    crypto.SHA512,
	"ripemd160": crypto.RIPEMD160,
}

var algorithmName map[crypto.Hash]string

func init() {
	algorithmName = make(map[crypto.Hash]string)
	for name, algorithm := range supportedAlgorithms {
		algorithmName[algorithm] = name
		// Make sure the algorithm is linked into the binary, per
		// https://golang.org/pkg/crypto/#Hash.Available
		//
		// Note that both sides of the client/server connection must
		// have an algorithm available in order to successfully
		// authenticate using that algorithm
		if algorithm.Available() == false {
			delete(supportedAlgorithms, name)
		}
	}
}

func DigestNameToCryptoHash(name string) (result crypto.Hash, err error) {
	var supported bool
	if result, supported = supportedAlgorithms[name]; !supported {
		err = errors.New("hmacauth: hash algorithm not supported: " +
			name)
	}
	return
}

func CryptoHashToDigestName(id crypto.Hash) (result string, err error) {
	var supported bool
	if result, supported = algorithmName[id]; !supported {
		err = errors.New("hmacauth: unsupported crypto.Hash #" +
			strconv.Itoa(int(id)))
	}
	return
}

type hmacAuth struct {
	hash    crypto.Hash
	key     []byte
	header  string
	headers []string
}

func NewHmacAuth(hash crypto.Hash, key []byte, header string,
	headers []string) HmacAuth {
	if hash.Available() == false {
		var name string
		var supported bool
		if name, supported = algorithmName[hash]; !supported {
			name = "#" + strconv.Itoa(int(hash))
		}
		panic("hmacauth: hash algorithm " + name + " is unavailable")
	}
	canonicalHeaders := make([]string, len(headers))
	for i, h := range headers {
		canonicalHeaders[i] = http.CanonicalHeaderKey(h)
	}
	return &hmacAuth{hash, key, header, canonicalHeaders}
}

func (auth *hmacAuth) StringToSign(req *http.Request) string {
	var buffer bytes.Buffer
	buffer.WriteString(req.Method)
	buffer.WriteString("\n")

	for _, header := range auth.headers {
		values := req.Header[header]
		lastIndex := len(values) - 1
		for i, value := range values {
			buffer.WriteString(value)
			if i != lastIndex {
				buffer.WriteString(",")
			}
		}
		buffer.WriteString("\n")
	}
	buffer.WriteString(req.URL.Path)
	if req.URL.RawQuery != "" {
		buffer.WriteString("?")
		buffer.WriteString(req.URL.RawQuery)
	}
	if req.URL.Fragment != "" {
		buffer.WriteString("#")
		buffer.WriteString(req.URL.Fragment)
	}
	buffer.WriteString("\n")
	return buffer.String()
}

type unsupportedAlgorithm struct {
	algorithm string
}

func (e unsupportedAlgorithm) Error() string {
	return "unsupported request signature algorithm: " + e.algorithm
}

func HashAlgorithm(algorithm string) (result crypto.Hash, err error) {
	if result = supportedAlgorithms[algorithm]; result == crypto.Hash(0) {
		err = unsupportedAlgorithm{algorithm}
	}
	return
}

func (auth *hmacAuth) SignRequest(req *http.Request) {
	req.Header.Set(auth.header, auth.RequestSignature(req))
}

func (auth *hmacAuth) RequestSignature(req *http.Request) string {
	return requestSignature(auth, req, auth.hash)
}

func requestSignature(auth *hmacAuth, req *http.Request,
	hashAlgorithm crypto.Hash) string {
	h := hmac.New(hashAlgorithm.New, auth.key)
	h.Write([]byte(auth.StringToSign(req)))

	if req.ContentLength != -1 && req.Body != nil {
		buf := make([]byte, req.ContentLength, req.ContentLength)
		req.Body.Read(buf)
		h.Write(buf)
	}

	var sig []byte
	sig = h.Sum(sig)
	return algorithmName[hashAlgorithm] + " " +
		base64.StdEncoding.EncodeToString(sig)
}

func (auth *hmacAuth) SignatureFromHeader(req *http.Request) string {
	return req.Header.Get(auth.header)
}

type ValidationResult int

const (
	NO_SIGNATURE ValidationResult = iota
	INVALID_FORMAT
	UNSUPPORTED_ALGORITHM
	MATCH
	MISMATCH
)

var validationResultStrings []string = []string{
	"",
	"NO_SIGNATURE",
	"INVALID_FORMAT",
	"UNSUPPORTED_ALGORITHM",
	"MATCH",
	"MISMATCH",
}

func (result ValidationResult) String() string {
	return validationResultStrings[result]
}

func (auth *hmacAuth) ValidateRequest(request *http.Request) (
	result ValidationResult, headerSignature, computedSignature string) {
	headerSignature = auth.SignatureFromHeader(request)
	if headerSignature == "" {
		result = NO_SIGNATURE
		return
	}

	components := strings.Split(headerSignature, " ")
	if len(components) != 2 {
		result = INVALID_FORMAT
		return
	}

	algorithm, err := HashAlgorithm(components[0])
	if err != nil {
		result = UNSUPPORTED_ALGORITHM
		return
	}

	computedSignature = requestSignature(auth, request, algorithm)
	if hmac.Equal([]byte(headerSignature), []byte(computedSignature)) {
		result = MATCH
	} else {
		result = MISMATCH
	}
	return
}
