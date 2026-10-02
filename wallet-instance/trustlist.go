package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// Relying Party trust following the EUDI Wallet model (ARF 6.6.3.2):
//   - the Wallet obtains the trust anchors of the Access Certificate Authorities from the
//     WRPAC Providers List of Trusted Entities (ETSI TS 119 602, JAdES-signed JSON)
//   - the Relying Party includes its access certificate (ETSI TS 119 411-8) in the request (x5c)
//   - the Wallet validates the chain up to a LoTE trust anchor and checks revocation (CRL)
// The LoTE signer (scheme operator) is trusted through OpenID Federation.

const (
	loteMediaType            = "application/jwt"
	loteTypeWRPACProviders   = "http://uri.etsi.org/19602/LoTEType/EUWRPACProvidersList"
	svcTypeWRPACIssuance     = "http://uri.etsi.org/19602/SvcType/WRPAC/Issuance"
	loteVersionIdentifier    = 1
	maxClockSkew             = 5 * time.Minute
	oidOrganizationIdentifer = "2.5.4.97"
)

// ETSI TS 119 411-8 WRPAC certificate policies.
var wrpacPolicies = []string{
	"0.4.0.194118.1.1", // NCP-n-eudiwrp
	"0.4.0.194118.1.2", // NCP-l-eudiwrp
	"0.4.0.194118.1.3", // QCP-n-eudiwrp
	"0.4.0.194118.1.4", // QCP-l-eudiwrp
}

type multiLang struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type loteDoc struct {
	ListAndSchemeInformation struct {
		LoTEVersionIdentifier int         `json:"LoTEVersionIdentifier"`
		LoTESequenceNumber    int         `json:"LoTESequenceNumber"`
		LoTEType              string      `json:"LoTEType"`
		SchemeOperatorName    []multiLang `json:"SchemeOperatorName"`
		SchemeTerritory       string      `json:"SchemeTerritory"`
		ListIssueDateTime     time.Time   `json:"ListIssueDateTime"`
		NextUpdate            time.Time   `json:"NextUpdate"`
	} `json:"ListAndSchemeInformation"`
	TrustedEntitiesList []struct {
		TrustedEntityInformation struct {
			TEName []multiLang `json:"TEName"`
		} `json:"TrustedEntityInformation"`
		TrustedEntityServices []struct {
			ServiceInformation struct {
				ServiceName            []multiLang `json:"ServiceName"`
				ServiceTypeIdentifier  string      `json:"ServiceTypeIdentifier"`
				ServiceStatus          string      `json:"ServiceStatus"`
				ServiceDigitalIdentity struct {
					X509Certificates []struct {
						Val string `json:"val"`
					} `json:"X509Certificates"`
				} `json:"ServiceDigitalIdentity"`
			} `json:"ServiceInformation"`
		} `json:"TrustedEntityServices"`
	} `json:"TrustedEntitiesList"`
}

// TrustAnchor is a WRPAC Provider (Access CA) certificate taken from the LoTE.
type TrustAnchor509 struct {
	EntityName string
	Cert       *x509.Certificate
}

// LoadedLoTE is a verified WRPAC Providers LoTE.
type LoadedLoTE struct {
	Location       string
	SequenceNumber int
	SchemeOperator string
	NextUpdate     time.Time
	Anchors        []TrustAnchor509
	FederationPath []string
}

func firstValue(v []multiLang) string {
	if len(v) == 0 {
		return ""
	}
	return v[0].Value
}

// verifyJAdESCompact verifies a JAdES baseline compact JWS: ES256, x5c signing certificate whose key
// must be one of trustedKeys, optional x5t#S256 binding, and the JAdES sigT header listed in crit.
func verifyJAdESCompact(jws string, trustedKeys *jose.JSONWebKeySet) ([]byte, *x509.Certificate, error) {
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return nil, nil, fmt.Errorf("not a compact JWS")
	}
	rawHeader, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, err
	}
	var header struct {
		Alg     string   `json:"alg"`
		X5c     []string `json:"x5c"`
		X5tS256 string   `json:"x5t#S256"`
		SigT    string   `json:"sigT"`
		Crit    []string `json:"crit"`
	}
	if err := json.Unmarshal(rawHeader, &header); err != nil {
		return nil, nil, err
	}
	if header.Alg != "ES256" {
		return nil, nil, fmt.Errorf("unsupported alg %q", header.Alg)
	}
	for _, c := range header.Crit { // RFC 7515 4.1.11: reject unknown critical parameters
		if c != "sigT" {
			return nil, nil, fmt.Errorf("unsupported critical header %q", c)
		}
	}
	if header.SigT == "" {
		return nil, nil, fmt.Errorf("JAdES sigT (claimed signing time) missing")
	}
	if len(header.X5c) == 0 {
		return nil, nil, fmt.Errorf("x5c (signing certificate) missing")
	}
	der, err := base64.StdEncoding.DecodeString(header.X5c[0])
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	if header.X5tS256 != "" {
		sum := sha256.Sum256(der)
		if base64.RawURLEncoding.EncodeToString(sum[:]) != header.X5tS256 {
			return nil, nil, fmt.Errorf("x5t#S256 does not match x5c")
		}
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("signing certificate is not EC")
	}
	// the scheme operator's key must be the one published in its federation metadata
	certJWK := jose.JSONWebKey{Key: pub}
	certThumb, _ := certJWK.Thumbprint(crypto.SHA256)
	trusted := false
	for _, k := range trustedKeys.Keys {
		pk := k.Public()
		if t, err := pk.Thumbprint(crypto.SHA256); err == nil && string(t) == string(certThumb) {
			trusted = true
		}
	}
	if !trusted {
		return nil, nil, fmt.Errorf("LoTE signing certificate key is not the scheme operator key from the federation")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		return nil, nil, fmt.Errorf("invalid ES256 signature encoding")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(pub, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return nil, nil, fmt.Errorf("LoTE signature verification failed")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	return payload, cert, err
}

// LoadWRPACProvidersLoTE locates the LoTE through the Trust List provider's federation metadata,
// verifies its JAdES signature and validity, and extracts the WRPAC issuance trust anchors.
func (i *Instance) LoadWRPACProvidersLoTE() (*LoadedLoTE, error) {
	chain, md, err := ResolveEntityType(i.state.TrustListProvider, "trust_list_provider", i.trustAnchor)
	if err != nil {
		return nil, fmt.Errorf("trust list provider is not trusted: %w", err)
	}
	jwks, err := JWKSFromMetadata(md)
	if err != nil {
		return nil, err
	}
	location := ""
	if locs, ok := md["lote_locations"].([]any); ok {
		for _, l := range locs {
			if m, ok := l.(map[string]any); ok && m["lote_type"] == loteTypeWRPACProviders {
				location, _ = m["location"].(string)
			}
		}
	}
	if location == "" {
		return nil, fmt.Errorf("trust list provider publishes no WRPAC Providers LoTE")
	}

	req, _ := http.NewRequest(http.MethodGet, location, nil)
	req.Header.Set("Accept", loteMediaType)
	resp, err := fedHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s -> %d", location, resp.StatusCode)
	}
	payload, _, err := verifyJAdESCompact(strings.TrimSpace(string(body)), jwks)
	if err != nil {
		return nil, fmt.Errorf("invalid LoTE signature: %w", err)
	}
	var claims struct {
		LoTE *loteDoc `json:"LoTE"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.LoTE == nil {
		return nil, fmt.Errorf("LoTE payload is not {\"LoTE\": ...}: %v", err)
	}
	lote := claims.LoTE
	info := lote.ListAndSchemeInformation
	now := time.Now()
	switch {
	case info.LoTEVersionIdentifier != loteVersionIdentifier:
		return nil, fmt.Errorf("unsupported LoTEVersionIdentifier %d", info.LoTEVersionIdentifier)
	case info.LoTEType != loteTypeWRPACProviders:
		return nil, fmt.Errorf("unexpected LoTEType %s", info.LoTEType)
	case info.ListIssueDateTime.After(now.Add(maxClockSkew)):
		return nil, fmt.Errorf("LoTE ListIssueDateTime is in the future")
	case !info.NextUpdate.After(now):
		return nil, fmt.Errorf("LoTE expired (NextUpdate %s)", info.NextUpdate.Format(time.RFC3339))
	}

	loaded := &LoadedLoTE{
		Location:       location,
		SequenceNumber: info.LoTESequenceNumber,
		SchemeOperator: firstValue(info.SchemeOperatorName),
		NextUpdate:     info.NextUpdate,
		FederationPath: chain.Path,
	}
	for _, te := range lote.TrustedEntitiesList {
		for _, svc := range te.TrustedEntityServices {
			si := svc.ServiceInformation
			if si.ServiceTypeIdentifier != svcTypeWRPACIssuance {
				continue
			}
			if si.ServiceStatus != "" && !strings.HasSuffix(si.ServiceStatus, "/granted") {
				continue
			}
			for _, c := range si.ServiceDigitalIdentity.X509Certificates {
				der, err := base64.StdEncoding.DecodeString(c.Val)
				if err != nil {
					return nil, fmt.Errorf("invalid X509Certificates value: %w", err)
				}
				cert, err := x509.ParseCertificate(der)
				if err != nil {
					return nil, err
				}
				// WRPAC Provider trust anchors are CA certificates (EU WRPAC LoTE profile)
				if !cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
					return nil, fmt.Errorf("WRPAC provider certificate %q is not a CA", cert.Subject)
				}
				loaded.Anchors = append(loaded.Anchors, TrustAnchor509{EntityName: firstValue(te.TrustedEntityInformation.TEName), Cert: cert})
			}
		}
	}
	if len(loaded.Anchors) == 0 {
		return nil, fmt.Errorf("LoTE contains no WRPAC issuance trust anchors")
	}
	return loaded, nil
}

// RelyingParty describes an authenticated Relying Party.
type RelyingParty struct {
	Organization           string
	OrganizationIdentifier string
	CommonName             string
	Policy                 string
	AccessCA               string
	AccessCAEntity         string
}

func (l *LoadedLoTE) Pool() *x509.CertPool {
	pool := x509.NewCertPool()
	for _, a := range l.Anchors {
		pool.AddCert(a.Cert)
	}
	return pool
}

// AuthenticateRelyingParty validates the access certificate in the request object x5c: WRPAC
// profile (ETSI TS 119 411-8) and certification path to a LoTE trust anchor. Revocation (CRL) is
// checked by the vcknots presenter when it verifies the request object.
func (l *LoadedLoTE) AuthenticateRelyingParty(requestObject, clientID string) (*RelyingParty, error) {
	parts := strings.Split(requestObject, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("request object is not a compact JWS")
	}
	rawHeader, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	var hdr struct {
		X5c []string `json:"x5c"`
	}
	if err := json.Unmarshal(rawHeader, &hdr); err != nil {
		return nil, err
	}
	x5c := hdr.X5c
	var chain []*x509.Certificate
	for _, c := range x5c {
		der, err := base64.StdEncoding.DecodeString(c)
		if err != nil {
			return nil, fmt.Errorf("invalid x5c: %w", err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		chain = append(chain, cert)
	}
	if len(chain) == 0 {
		return nil, fmt.Errorf("request object carries no access certificate (x5c)")
	}
	leaf := chain[0]

	// WRPAC profile checks
	if leaf.IsCA {
		return nil, fmt.Errorf("access certificate must be an end-entity certificate")
	}
	if leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return nil, fmt.Errorf("access certificate lacks digitalSignature key usage")
	}
	if leaf.Subject.String() == leaf.Issuer.String() {
		return nil, fmt.Errorf("access certificate must not be self-signed")
	}
	policy := ""
	for _, p := range leaf.Policies {
		if slices.Contains(wrpacPolicies, p.String()) {
			policy = p.String()
		}
	}
	if policy == "" {
		return nil, fmt.Errorf("access certificate has no ETSI TS 119 411-8 WRPAC policy")
	}
	if dns, ok := strings.CutPrefix(clientID, "x509_san_dns:"); !ok || !slices.Contains(leaf.DNSNames, dns) {
		return nil, fmt.Errorf("client_id %q does not match the access certificate SAN", clientID)
	}

	// certification path up to a LoTE trust anchor (intermediates from x5c)
	intermediates := x509.NewCertPool()
	for _, c := range chain[1:] {
		intermediates.AddCert(c)
	}
	paths, err := leaf.Verify(x509.VerifyOptions{
		Roots:         l.Pool(),
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return nil, fmt.Errorf("access certificate is not issued by a WRPAC provider in the LoTE: %w", err)
	}
	anchor := paths[0][len(paths[0])-1]
	rp := &RelyingParty{
		CommonName: leaf.Subject.CommonName,
		Policy:     policy,
		AccessCA:   anchor.Subject.CommonName,
	}
	if len(leaf.Subject.Organization) > 0 {
		rp.Organization = leaf.Subject.Organization[0]
	}
	for _, n := range leaf.Subject.Names {
		if n.Type.String() == oidOrganizationIdentifer {
			rp.OrganizationIdentifier = fmt.Sprint(n.Value)
		}
	}
	for _, a := range l.Anchors {
		if a.Cert.Equal(anchor) {
			rp.AccessCAEntity = a.EntityName
		}
	}
	return rp, nil
}
