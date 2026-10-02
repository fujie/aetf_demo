package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// OpenID Federation 1.0 Trust Chain resolution (wallet side).

const (
	entityStatementTyp  = "entity-statement+jwt"
	wellKnownFederation = "/.well-known/openid-federation"
	maxPathLength       = 5
)

// TrustAnchor is the out-of-band configured Trust Anchor (eduGAIN).
type TrustAnchor struct {
	EntityID string             `json:"entityId"`
	JWKS     jose.JSONWebKeySet `json:"jwks"`
}

type entityStatement struct {
	Iss            string                               `json:"iss"`
	Sub            string                               `json:"sub"`
	Exp            int64                                `json:"exp"`
	JWKS           *jose.JSONWebKeySet                  `json:"jwks"`
	Metadata       map[string]map[string]any            `json:"metadata"`
	MetadataPolicy map[string]map[string]map[string]any `json:"metadata_policy"`
	AuthorityHints []string                             `json:"authority_hints"`
}

type signedStatement struct {
	raw     string
	payload entityStatement
}

// ResolvedChain is a validated Trust Chain with the resolved (policy applied) metadata.
type ResolvedChain struct {
	EntityID string
	Path     []string
	Metadata map[string]map[string]any
}

var fedHTTPClient = &http.Client{Timeout: 10 * time.Second}

func fetchText(u string) (string, error) {
	resp, err := fedHTTPClient.Get(u)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET %s -> %d", u, resp.StatusCode)
	}
	return strings.TrimSpace(string(body)), nil
}

// verifyJWS verifies a compact JWS with a key from jwks (selected by kid) and returns the payload.
func verifyJWS(raw string, jwks *jose.JSONWebKeySet, expectedTyp string) ([]byte, error) {
	if jwks == nil || len(jwks.Keys) == 0 {
		return nil, fmt.Errorf("no keys to verify JWS")
	}
	jws, err := jose.ParseSigned(raw, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return nil, err
	}
	hdr := jws.Signatures[0].Protected
	if expectedTyp != "" {
		if typ, _ := hdr.ExtraHeaders[jose.HeaderType].(string); typ != expectedTyp {
			return nil, fmt.Errorf("unexpected typ %q (want %q)", typ, expectedTyp)
		}
	}
	candidates := jwks.Keys
	if hdr.KeyID != "" {
		candidates = jwks.Key(hdr.KeyID)
	}
	for _, k := range candidates {
		if payload, err := jws.Verify(k); err == nil {
			return payload, nil
		}
	}
	return nil, fmt.Errorf("signature verification failed (kid=%q)", hdr.KeyID)
}

func parseStatement(raw string, jwks *jose.JSONWebKeySet) (*signedStatement, error) {
	payload, err := verifyJWS(raw, jwks, entityStatementTyp)
	if err != nil {
		return nil, err
	}
	var st entityStatement
	if err := json.Unmarshal(payload, &st); err != nil {
		return nil, err
	}
	if st.Exp != 0 && time.Unix(st.Exp, 0).Before(time.Now()) {
		return nil, fmt.Errorf("statement %s/%s expired", st.Iss, st.Sub)
	}
	return &signedStatement{raw: raw, payload: st}, nil
}

// unverifiedJWKS extracts the jwks claim of a self-signed Entity Configuration before verification.
func unverifiedJWKS(raw string) (*jose.JSONWebKeySet, error) {
	jws, err := jose.ParseSigned(raw, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return nil, err
	}
	var st entityStatement
	if err := json.Unmarshal(jws.UnsafePayloadWithoutVerification(), &st); err != nil {
		return nil, err
	}
	return st.JWKS, nil
}

func fetchEntityConfiguration(entityID string) (*signedStatement, error) {
	raw, err := fetchText(strings.TrimSuffix(entityID, "/") + wellKnownFederation)
	if err != nil {
		return nil, err
	}
	jwks, err := unverifiedJWKS(raw)
	if err != nil {
		return nil, err
	}
	ec, err := parseStatement(raw, jwks)
	if err != nil {
		return nil, err
	}
	if ec.payload.Iss != entityID || ec.payload.Sub != entityID {
		return nil, fmt.Errorf("entity configuration iss/sub mismatch for %s", entityID)
	}
	return ec, nil
}

// resolveUpwards returns subordinate statements [SS(entity), SS(superior), ...] and the path to the TA.
func resolveUpwards(ec *signedStatement, ta TrustAnchor, depth int, errs *[]string) ([]*signedStatement, []string, bool) {
	id := ec.payload.Sub
	if id == ta.EntityID {
		if _, err := verifyJWS(ec.raw, &ta.JWKS, entityStatementTyp); err != nil {
			*errs = append(*errs, "trust anchor key mismatch: "+err.Error())
			return nil, nil, false
		}
		return nil, []string{id}, true
	}
	if depth > maxPathLength {
		*errs = append(*errs, "max path length exceeded")
		return nil, nil, false
	}
	for _, authority := range ec.payload.AuthorityHints {
		superior, err := fetchEntityConfiguration(authority)
		if err != nil {
			*errs = append(*errs, fmt.Sprintf("%s: %v", authority, err))
			continue
		}
		fetchEndpoint, _ := superior.payload.Metadata["federation_entity"]["federation_fetch_endpoint"].(string)
		if fetchEndpoint == "" {
			*errs = append(*errs, authority+" has no federation_fetch_endpoint")
			continue
		}
		raw, err := fetchText(fetchEndpoint + "?sub=" + url.QueryEscape(id))
		if err != nil {
			*errs = append(*errs, err.Error())
			continue
		}
		ss, err := parseStatement(raw, superior.payload.JWKS)
		if err != nil || ss.payload.Iss != authority || ss.payload.Sub != id {
			*errs = append(*errs, fmt.Sprintf("invalid subordinate statement from %s: %v", authority, err))
			continue
		}
		// The superior vouches for the keys that signed the subordinate's Entity Configuration.
		if _, err := verifyJWS(ec.raw, ss.payload.JWKS, entityStatementTyp); err != nil {
			*errs = append(*errs, fmt.Sprintf("%s EC not signed by keys in statement from %s", id, authority))
			continue
		}
		upper, path, ok := resolveUpwards(superior, ta, depth+1, errs)
		if !ok {
			continue
		}
		return append([]*signedStatement{ss}, upper...), append([]string{id}, path...), true
	}
	return nil, nil, false
}

// ResolveTrustChain validates a Trust Chain from entityID to the Trust Anchor and applies metadata policies.
func ResolveTrustChain(entityID string, ta TrustAnchor) (*ResolvedChain, error) {
	leaf, err := fetchEntityConfiguration(entityID)
	if err != nil {
		return nil, err
	}
	var errs []string
	statements, path, ok := resolveUpwards(leaf, ta, 0, &errs)
	if !ok {
		return nil, fmt.Errorf("no valid trust chain for %s: %s", entityID, strings.Join(errs, "; "))
	}
	metadata := leaf.payload.Metadata
	if metadata == nil {
		metadata = map[string]map[string]any{}
	}
	if len(statements) > 0 {
		for typ, params := range statements[0].payload.Metadata {
			if metadata[typ] == nil {
				metadata[typ] = map[string]any{}
			}
			for k, v := range params {
				metadata[typ][k] = v
			}
		}
	}
	// apply policies, Trust Anchor first
	for i := len(statements) - 1; i >= 0; i-- {
		if err := applyPolicy(metadata, statements[i].payload.MetadataPolicy); err != nil {
			return nil, err
		}
	}
	return &ResolvedChain{EntityID: entityID, Path: path, Metadata: metadata}, nil
}

// ResolveEntityType resolves a chain and requires metadata for entityType.
func ResolveEntityType(entityID, entityType string, ta TrustAnchor) (*ResolvedChain, map[string]any, error) {
	chain, err := ResolveTrustChain(entityID, ta)
	if err != nil {
		return nil, nil, err
	}
	md, ok := chain.Metadata[entityType]
	if !ok {
		return nil, nil, fmt.Errorf("%s is not registered as %s in the federation", entityID, entityType)
	}
	return chain, md, nil
}

// JWKSFromMetadata extracts a jwks parameter from resolved metadata.
func JWKSFromMetadata(md map[string]any) (*jose.JSONWebKeySet, error) {
	raw, err := json.Marshal(md["jwks"])
	if err != nil {
		return nil, err
	}
	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal(raw, &jwks); err != nil {
		return nil, err
	}
	if len(jwks.Keys) == 0 {
		return nil, fmt.Errorf("metadata has no jwks")
	}
	return &jwks, nil
}

// --- metadata policy (subset: value, add, default, one_of, subset_of, superset_of, essential) ---

func asSlice(v any) []any {
	if s, ok := v.([]any); ok {
		return s
	}
	return []any{v}
}

func contains(list []any, v any) bool {
	for _, x := range list {
		if reflect.DeepEqual(x, v) {
			return true
		}
	}
	return false
}

func applyPolicy(metadata map[string]map[string]any, policy map[string]map[string]map[string]any) error {
	for typ, params := range policy {
		md, ok := metadata[typ]
		if !ok {
			continue
		}
		for param, ops := range params {
			cur, present := md[param]
			if v, ok := ops["value"]; ok {
				if v == nil {
					delete(md, param)
					present = false
				} else {
					md[param], cur, present = v, v, true
				}
			}
			if v, ok := ops["add"]; ok {
				list := []any{}
				if present {
					list = asSlice(cur)
				}
				for _, x := range asSlice(v) {
					if !contains(list, x) {
						list = append(list, x)
					}
				}
				md[param], cur, present = list, list, true
			}
			if v, ok := ops["default"]; ok && !present {
				md[param], cur, present = v, v, true
			}
			if v, ok := ops["one_of"]; ok && present && !contains(asSlice(v), cur) {
				return fmt.Errorf("%s.%s violates one_of", typ, param)
			}
			if v, ok := ops["subset_of"]; ok && present {
				var out []any
				for _, x := range asSlice(cur) {
					if contains(asSlice(v), x) {
						out = append(out, x)
					}
				}
				if len(out) == 0 {
					delete(md, param)
					present = false
				} else {
					md[param], cur = out, out
				}
			}
			if v, ok := ops["superset_of"]; ok && present {
				for _, x := range asSlice(v) {
					if !contains(asSlice(cur), x) {
						return fmt.Errorf("%s.%s violates superset_of", typ, param)
					}
				}
			}
			if v, ok := ops["essential"].(bool); ok && v && !present {
				return fmt.Errorf("%s.%s is essential but missing", typ, param)
			}
		}
	}
	return nil
}
