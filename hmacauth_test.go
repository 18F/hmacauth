package hmacauth

import (
	"bufio"
	"crypto"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/bmizerany/assert"
)

// These correspond to the headers used in bitly/oauth2_proxy#147.
var HEADERS []string = []string{
	"Content-Length",
	"Content-Md5",
	"Content-Type",
	"Date",
	"Authorization",
	"X-Forwarded-User",
	"X-Forwarded-Email",
	"X-Forwarded-Access-Token",
	"Cookie",
	"Gap-Auth",
}

func TestSupportedHashAlgorithm(t *testing.T) {
	algorithm, err := HashAlgorithm("sha1")
	assert.Equal(t, err, nil)
	assert.Equal(t, algorithm, crypto.SHA1)
	assert.Equal(t, algorithm.Available(), true)
}

func TestUnsupportedHashAlgorithm(t *testing.T) {
	algorithm, err := HashAlgorithm("unsupported")
	assert.NotEqual(t, err, nil)
	assert.Equal(t, err.Error(),
		"unsupported request signature algorithm: unsupported")
	assert.Equal(t, algorithm, crypto.Hash(0))
	assert.Equal(t, algorithm.Available(), false)
}

func newTestRequest(request ...string) (req *http.Request) {
	reqBuf := bufio.NewReader(
		strings.NewReader(strings.Join(request, "\n")))
	if req, err := http.ReadRequest(reqBuf); err != nil {
		panic(err)
	} else {
		return req
	}
}

func testHmacAuth() *HmacAuth {
	return NewHmacAuth(
		crypto.SHA1, []byte("foobar"), "GAP-Signature", HEADERS)
}

func TestRequestSignaturePost(t *testing.T) {
	body := `{ "hello": "world!" }`
	req := newTestRequest(
		"POST /foo/bar HTTP/1.1",
		"Content-Length: "+strconv.Itoa(len(body)),
		"Content-MD5: deadbeef",
		"Content-Type: application/json",
		"Date: 2015-09-28",
		"Authorization: trust me",
		"X-Forwarded-User: mbland",
		"X-Forwarded-Email: mbland@acm.org",
		"X-Forwarded-Access-Token: feedbead",
		"Cookie: foo; bar; baz=quux",
		"Gap-Auth: mbland",
		"",
		body,
	)

	h := testHmacAuth()
	assert.Equal(t, h.StringToSign(req), strings.Join([]string{
		"POST",
		strconv.Itoa(len(body)),
		"deadbeef",
		"application/json",
		"2015-09-28",
		"trust me",
		"mbland",
		"mbland@acm.org",
		"feedbead",
		"foo; bar; baz=quux",
		"mbland",
		"/foo/bar",
	}, "\n"))
	assert.Equal(t, h.RequestSignature(req),
		"sha1 722UbRYfC6MnjtIxqEJMDPrW2mk=")
}

func newGetRequest() *http.Request {
	return newTestRequest(
		"GET /foo/bar HTTP/1.1",
		"Date: 2015-09-29",
		"Cookie: foo; bar; baz=quux",
		"Gap-Auth: mbland",
		"",
		"",
	)
}

func TestRequestSignatureGetWithFullUrl(t *testing.T) {
	req := newTestRequest(
		"GET http://localhost/foo/bar?baz=quux#xyzzy HTTP/1.1",
		"Date: 2015-09-29",
		"Cookie: foo; bar; baz=quux",
		"Gap-Auth: mbland",
		"",
		"",
	)

	h := testHmacAuth()
	assert.Equal(t, h.StringToSign(req), strings.Join([]string{
		"GET",
		"",
		"",
		"",
		"2015-09-29",
		"",
		"",
		"",
		"",
		"foo; bar; baz=quux",
		"mbland",
		"/foo/bar?baz=quux#xyzzy",
	}, "\n"))
	assert.Equal(t, h.RequestSignature(req),
		"sha1 gw1nuRYzkocv5q8nQSo3pT5F970=")
}

func TestRequestSignatureGetWithMultipleHeadersWithTheSameName(t *testing.T) {
	// Just using "Cookie:" out of convenience.
	req := newTestRequest(
		"GET /foo/bar HTTP/1.1",
		"Date: 2015-09-29",
		"Cookie: foo",
		"Cookie: bar",
		"Cookie: baz=quux",
		"Gap-Auth: mbland",
		"",
		"",
	)

	h := testHmacAuth()
	assert.Equal(t, h.StringToSign(req), strings.Join([]string{
		"GET",
		"",
		"",
		"",
		"2015-09-29",
		"",
		"",
		"",
		"",
		"foo,bar,baz=quux",
		"mbland",
		"/foo/bar",
	}, "\n"))
	assert.Equal(t, h.RequestSignature(req),
		"sha1 VnoxQC+mg2Oils+Cbz1j1c9LXLE=")
}

func TestValidateRequestNoSignature(t *testing.T) {
	h := testHmacAuth()
	req := newGetRequest()
	result, header, computed := h.ValidateRequest(req)
	assert.Equal(t, result, NO_SIGNATURE)
	assert.Equal(t, header, "")
	assert.Equal(t, computed, "")
}

func TestValidateRequestInvalidFormat(t *testing.T) {
	h := testHmacAuth()
	req := newGetRequest()
	badValue := "should be algorithm and digest value"
	req.Header.Set("GAP-Signature", badValue)
	result, header, computed := h.ValidateRequest(req)
	assert.Equal(t, result, INVALID_FORMAT)
	assert.Equal(t, header, badValue)
	assert.Equal(t, computed, "")
}

func TestValidateRequestUnsupportedAlgorithm(t *testing.T) {
	h := testHmacAuth()
	req := newGetRequest()
	validSignature := h.RequestSignature(req)
	components := strings.Split(validSignature, " ")
	signatureWithUnsupportedAlgorithm := "unsupported " + components[1]
	req.Header.Set("GAP-Signature", signatureWithUnsupportedAlgorithm)
	result, header, computed := h.ValidateRequest(req)
	assert.Equal(t, result, UNSUPPORTED_ALGORITHM)
	assert.Equal(t, header, signatureWithUnsupportedAlgorithm)
	assert.Equal(t, computed, "")
}

func TestValidateRequestMatch(t *testing.T) {
	h := testHmacAuth()
	req := newGetRequest()
	expected := h.RequestSignature(req)
	h.SignRequest(req)
	result, header, computed := h.ValidateRequest(req)
	assert.Equal(t, result, MATCH)
	assert.Equal(t, header, expected)
	assert.Equal(t, computed, expected)
}

func TestValidateRequestMismatch(t *testing.T) {
	foobarAuth := testHmacAuth()
	barbazAuth := NewHmacAuth(
		crypto.SHA1, []byte("barbaz"), "GAP-Signature", HEADERS)
	req := newGetRequest()
	foobarAuth.SignRequest(req)
	result, header, computed := barbazAuth.ValidateRequest(req)
	assert.Equal(t, result, MISMATCH)
	assert.Equal(t, header, foobarAuth.RequestSignature(req))
	assert.Equal(t, computed, barbazAuth.RequestSignature(req))
}
