package main

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Token Status List (draft-ietf-oauth-status-list), Holder side.

const (
	statusListTyp       = "statuslist+jwt"
	statusListMediaType = "application/statuslist+jwt"
)

// StatusList is a decoded (uncompressed) Status List.
type StatusList struct {
	Bits  int
	Bytes []byte
}

// DecodeStatusList decodes the JSON StatusList structure (base64url + ZLIB/DEFLATE).
func DecodeStatusList(bits int, lst string) (*StatusList, error) {
	switch bits {
	case 1, 2, 4, 8:
	default:
		return nil, fmt.Errorf("invalid bits %d", bits)
	}
	compressed, err := base64.RawURLEncoding.DecodeString(lst)
	if err != nil {
		return nil, fmt.Errorf("lst is not base64url: %w", err)
	}
	r, err := zlib.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, fmt.Errorf("lst is not ZLIB: %w", err)
	}
	defer r.Close()
	raw, err := io.ReadAll(io.LimitReader(r, 64<<20))
	if err != nil {
		return nil, err
	}
	return &StatusList{Bits: bits, Bytes: raw}, nil
}

// Size is the number of statuses in the list.
func (s *StatusList) Size() int { return len(s.Bytes) * 8 / s.Bits }

// Get returns the status at idx; statuses are packed from the least significant bit.
func (s *StatusList) Get(idx int) (int, error) {
	if idx < 0 || idx >= s.Size() {
		return 0, fmt.Errorf("index %d out of bounds (size %d)", idx, s.Size())
	}
	perByte := 8 / s.Bits
	shift := (idx % perByte) * s.Bits
	return int(s.Bytes[idx/perByte]>>shift) & (1<<s.Bits - 1), nil
}

// StatusTypeName maps Status Type values (section 7.1).
func StatusTypeName(v int) string {
	switch {
	case v == 0x00:
		return "VALID"
	case v == 0x01:
		return "INVALID"
	case v == 0x02:
		return "SUSPENDED"
	case v == 0x03 || (v >= 0x0c && v <= 0x0f):
		return fmt.Sprintf("APPLICATION_SPECIFIC(0x%02x)", v)
	default:
		return fmt.Sprintf("UNKNOWN(0x%02x)", v)
	}
}

// StatusResult is the evaluated status of a Referenced Token.
type StatusResult struct {
	Idx          int
	URI          string
	Status       int
	StatusIssuer string
	ChainPath    []string
}

func fetchStatusListToken(uri string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, uri, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", statusListMediaType)
	resp, err := fedHTTPClient.Do(req) // follows up to 10 redirects
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("GET %s -> %d", uri, resp.StatusCode)
	}
	if ct := strings.ToLower(strings.TrimSpace(strings.Split(resp.Header.Get("Content-Type"), ";")[0])); ct != statusListMediaType {
		return "", fmt.Errorf("unexpected content-type %q", ct)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	return strings.TrimSpace(string(body)), err
}

// CheckStatus evaluates the status of a Referenced Token payload following the validation rules
// of section 8.3. The Status Issuer key is resolved through OpenID Federation.
func (i *Instance) CheckStatus(referencedToken map[string]any) (*StatusResult, error) {
	// 1. status / status_list / idx / uri
	status, _ := referencedToken["status"].(map[string]any)
	ref, _ := status["status_list"].(map[string]any)
	if ref == nil {
		return nil, fmt.Errorf("no status.status_list claim")
	}
	idxF, ok := ref["idx"].(float64)
	if !ok || idxF < 0 || idxF != float64(int(idxF)) {
		return nil, fmt.Errorf("status_list.idx must be a non-negative integer")
	}
	uri, _ := ref["uri"].(string)
	if _, err := url.ParseRequestURI(uri); err != nil {
		return nil, fmt.Errorf("status_list.uri must be a URI")
	}
	idx := int(idxF)

	// 2. resolve the Status List Token
	token, err := fetchStatusListToken(uri)
	if err != nil {
		return nil, err
	}
	// 3. validate: key via federation (Status Issuer = iss), typ, signature, required claims
	var unverified struct {
		Iss string `json:"iss"`
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("Status List Token is not a compact JWS")
	}
	if b, err := base64.RawURLEncoding.DecodeString(parts[1]); err != nil || json.Unmarshal(b, &unverified) != nil || unverified.Iss == "" {
		return nil, fmt.Errorf("Status List Token has no iss")
	}
	if !strings.HasPrefix(uri, strings.TrimSuffix(unverified.Iss, "/")+"/") {
		return nil, fmt.Errorf("Status List Token URI is not hosted under its Status Issuer")
	}
	chain, md, err := ResolveEntityType(unverified.Iss, "status_list_provider", i.trustAnchor)
	if err != nil {
		return nil, fmt.Errorf("status issuer is not trusted: %w", err)
	}
	jwks, err := JWKSFromMetadata(md)
	if err != nil {
		return nil, err
	}
	payload, err := verifyJWS(token, jwks, statusListTyp)
	if err != nil {
		return nil, fmt.Errorf("invalid Status List Token: %w", err)
	}
	var claims struct {
		Sub        string   `json:"sub"`
		Iat        *int64   `json:"iat"`
		Exp        *int64   `json:"exp"`
		TTL        *float64 `json:"ttl"`
		StatusList *struct {
			Bits int    `json:"bits"`
			Lst  string `json:"lst"`
		} `json:"status_list"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}
	if claims.Sub == "" || claims.Iat == nil || claims.StatusList == nil {
		return nil, fmt.Errorf("Status List Token is missing sub/iat/status_list")
	}
	// 4. sub == uri, exp, ttl
	if claims.Sub != uri {
		return nil, fmt.Errorf("Status List Token sub %q != %q", claims.Sub, uri)
	}
	if claims.Exp != nil && time.Unix(*claims.Exp, 0).Before(time.Now()) {
		return nil, fmt.Errorf("Status List Token expired")
	}
	if claims.TTL != nil && *claims.TTL <= 0 {
		return nil, fmt.Errorf("ttl must be positive")
	}
	// 5. decompress, 6. index lookup (out of bounds -> reject)
	list, err := DecodeStatusList(claims.StatusList.Bits, claims.StatusList.Lst)
	if err != nil {
		return nil, err
	}
	value, err := list.Get(idx)
	if err != nil {
		return nil, err
	}
	return &StatusResult{Idx: idx, URI: uri, Status: value, StatusIssuer: unverified.Iss, ChainPath: chain.Path}, nil
}
