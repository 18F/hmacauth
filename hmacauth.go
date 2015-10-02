package hmacauth

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"
)

var supportedAlgorithms map[string]crypto.Hash
var algorithmName map[crypto.Hash]string

func init() {
	supportedAlgorithms = map[string]crypto.Hash{
		"sha1": crypto.SHA1,
	}

	algorithmName = make(map[crypto.Hash]string)
	for name, algorithm := range supportedAlgorithms {
		algorithmName[algorithm] = name
	}
}

func StringToSign(req *http.Request, headers []string) string {
	var buffer bytes.Buffer
	buffer.WriteString(req.Method)
	buffer.WriteString("\n")

	for _, header := range headers {
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

func RequestSignature(req *http.Request, hashAlgorithm crypto.Hash,
	headers []string, secretKey string) string {
	h := hmac.New(hashAlgorithm.New, []byte(secretKey))
	h.Write([]byte(StringToSign(req, headers)))

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

type ValidationResult int

const (
	NO_SIGNATURE ValidationResult = iota
	INVALID_FORMAT
	UNSUPPORTED_ALGORITHM
	MATCH
	MISMATCH
)

func (result ValidationResult) String() string {
	return strconv.Itoa(int(result))
}

func ValidateRequest(request *http.Request, headers []string, key string) (
	result ValidationResult, headerSignature, computedSignature string) {
	headerSignature = request.Header.Get("Gap-Signature")
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

	computedSignature = RequestSignature(request, algorithm, headers, key)
	if hmac.Equal([]byte(headerSignature), []byte(computedSignature)) {
		result = MATCH
	} else {
		result = MISMATCH
	}
	return
}
