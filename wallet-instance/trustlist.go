package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const trustListTyp = "trust-list+jwt"

type TrustListEntry struct {
	ClientID          string   `json:"client_id"`
	Name              string   `json:"name"`
	X5C               []string `json:"x5c"`
	ResponseURIOrigin string   `json:"response_uri_origin"`
}

// LookupVerifier fetches the Trust List, validates its signer through OpenID Federation and
// returns the entry for clientID together with a cert pool for the vcknots x5c verification.
func (i *Instance) LookupVerifier(clientID string) (*TrustListEntry, *x509.CertPool, error) {
	chain, md, err := ResolveEntityType(i.state.TrustListProvider, "trust_list_provider", i.trustAnchor)
	if err != nil {
		return nil, nil, fmt.Errorf("trust list provider is not trusted: %w", err)
	}
	fmt.Printf("✔ Trust List provider trusted via OpenID Federation: %s\n", strings.Join(chain.Path, " -> "))
	endpoint, _ := md["trust_list_endpoint"].(string)
	raw, err := fetchText(endpoint)
	if err != nil {
		return nil, nil, err
	}
	jwks, err := JWKSFromMetadata(md)
	if err != nil {
		return nil, nil, err
	}
	payload, err := verifyJWS(raw, jwks, trustListTyp)
	if err != nil {
		return nil, nil, fmt.Errorf("trust list signature invalid: %w", err)
	}
	var list struct {
		Iss     string           `json:"iss"`
		Exp     int64            `json:"exp"`
		Entries []TrustListEntry `json:"entries"`
	}
	if err := json.Unmarshal(payload, &list); err != nil {
		return nil, nil, err
	}
	if list.Iss != i.state.TrustListProvider || time.Unix(list.Exp, 0).Before(time.Now()) {
		return nil, nil, fmt.Errorf("trust list iss/exp invalid")
	}
	for _, e := range list.Entries {
		if e.ClientID != clientID {
			continue
		}
		pool := x509.NewCertPool()
		for _, c := range e.X5C {
			der, err := base64.StdEncoding.DecodeString(c)
			if err != nil {
				return nil, nil, err
			}
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				return nil, nil, err
			}
			pool.AddCert(cert)
		}
		return &e, pool, nil
	}
	return nil, nil, fmt.Errorf("verifier %q is not registered in the Trust List", clientID)
}
