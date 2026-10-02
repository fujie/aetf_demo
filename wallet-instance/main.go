// Command wallet-instance is the Wallet Instance (Holder) of the IHV prototype.
//
// It is built on the vcknots Go wallet library (OID4VCI / OID4VP, SD-JWT VC) and adds:
//   - Wallet Attestation obtained from the Wallet Provider (trusted via OpenID Federation)
//     and presented to the Issuer / Verifier as attestation-based client authentication
//   - Issuer trust check via OpenID Federation before accepting a Credential Offer
//   - Verifier trust check via the Trust List (whose signer is trusted via OpenID Federation)
package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/credstore"
	"github.com/trustknots/vcknots/wallet/credstore/plugins/local"
	"github.com/trustknots/vcknots/wallet/env"
	"github.com/trustknots/vcknots/wallet/presenter"
	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp"
	"github.com/trustknots/vcknots/wallet/receiver"
	"github.com/trustknots/vcknots/wallet/serializer/plugins/sdjwtvc"
)

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func usage() {
	fmt.Fprintf(os.Stderr, `usage: wallet-instance <command> [args]

commands:
  init                         register with the Wallet Provider and obtain a Wallet Attestation
  receive '<credential offer>' receive a credential (OID4VCI pre-authorized code flow)
  present '<openid4vp uri>' [--claims a,b,c]
                               present the latest credential (OID4VP, SD-JWT VC + KB-JWT)
  list                         list stored credentials

environment:
  WALLET_DIR       wallet data directory (default ./.wallet)
  TRUST_ANCHOR     trust anchor config  (default ../.data/trust-anchor.json)
  WALLET_PROVIDER  Wallet Provider entity id (default http://localhost:7030)
  TRUST_LIST       Trust List provider entity id (default http://localhost:7031)
`)
	os.Exit(2)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	// The prototype runs every entity on http://localhost.
	env.SetHTTPAllowed(true)

	inst, err := openInstance(
		getenv("WALLET_DIR", ".wallet"),
		getenv("TRUST_ANCHOR", filepath.Join("..", ".data", "trust-anchor.json")),
	)
	if err == nil {
		inst.state.WalletProvider = getenv("WALLET_PROVIDER", "http://localhost:7030")
		inst.state.TrustListProvider = getenv("TRUST_LIST", "http://localhost:7031")
		switch os.Args[1] {
		case "init":
			err = inst.RefreshAttestation()
		case "receive":
			if len(os.Args) < 3 {
				usage()
			}
			err = inst.receive(os.Args[2])
		case "present":
			if len(os.Args) < 3 {
				usage()
			}
			var claims []string
			if len(os.Args) >= 5 && os.Args[3] == "--claims" {
				claims = strings.Split(os.Args[4], ",")
			}
			err = inst.present(os.Args[2], claims)
		case "list":
			err = inst.list()
		default:
			usage()
		}
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "✘ %v\n", err)
		os.Exit(1)
	}
}

func (i *Instance) newWallet(x509Roots *oid4vpRoots) (*wallet.Wallet, error) {
	store, err := local.NewLocalCredentialStorage(filepath.Join(i.dir, "credstore.db"))
	if err != nil {
		return nil, err
	}
	credStore, err := credstore.NewCredStoreDispatcher(credstore.WithPlugin(local.Local, store))
	if err != nil {
		return nil, err
	}
	cfg := wallet.Config{CredStore: credStore}
	if x509Roots != nil {
		p, err := presenter.NewPresentationDispatcher(
			presenter.WithPlugin(presenter.Oid4vp, &oid4vp.Oid4vpPresenter{X509TrustChainRoots: x509Roots.pool}),
		)
		if err != nil {
			return nil, err
		}
		cfg.Presenter = p
	}
	return wallet.NewWalletWithConfig(cfg)
}

// ---- receive ---------------------------------------------------------------------------------

func (i *Instance) receive(offerURI string) error {
	parsed, err := url.Parse(offerURI)
	if err != nil {
		return err
	}
	var offerJSON struct {
		CredentialIssuer           string                                  `json:"credential_issuer"`
		CredentialConfigurationIDs []string                                `json:"credential_configuration_ids"`
		Grants                     map[string]*wallet.CredentialOfferGrant `json:"grants"`
	}
	if err := json.Unmarshal([]byte(parsed.Query().Get("credential_offer")), &offerJSON); err != nil {
		return fmt.Errorf("invalid credential offer: %w", err)
	}

	// 1. Is the issuer a member of the federation (openid_credential_issuer)?
	chain, _, err := ResolveEntityType(offerJSON.CredentialIssuer, "openid_credential_issuer", i.trustAnchor)
	if err != nil {
		return fmt.Errorf("issuer is not trusted: %w", err)
	}
	fmt.Printf("✔ Issuer trusted via OpenID Federation: %s\n", strings.Join(chain.Path, " -> "))

	// 2. Wallet Attestation for attestation-based client authentication at the token endpoint
	if err := i.EnsureAttestation(); err != nil {
		return err
	}
	installAttestationTransport(i)

	issuerURL, err := url.Parse(offerJSON.CredentialIssuer)
	if err != nil {
		return err
	}
	w, err := i.newWallet(nil)
	if err != nil {
		return err
	}
	saved, err := w.ReceiveCredential(wallet.ReceiveCredentialRequest{
		CredentialOffer: &wallet.CredentialOffer{
			CredentialIssuer:           issuerURL,
			CredentialConfigurationIDs: offerJSON.CredentialConfigurationIDs,
			Grants:                     offerJSON.Grants,
		},
		Type:            receiver.Oid4vci,
		Key:             i.holderKey,
		RequestedFormat: credential.SDJwtVC,
	})
	if err != nil {
		return fmt.Errorf("receive failed: %w", err)
	}
	fmt.Printf("✔ Credential received and stored: %s\n", saved.Entry.Id)
	printCredential(saved.Entry.Raw)
	return nil
}

// ---- present ---------------------------------------------------------------------------------

type oid4vpRoots struct{ pool *x509.CertPool }

func (i *Instance) present(requestURI string, claims []string) error {
	parsed, err := url.Parse(requestURI)
	if err != nil {
		return err
	}
	q := parsed.Query()
	clientID := q.Get("client_id")
	if clientID == "" {
		return fmt.Errorf("client_id missing in authorization request")
	}

	// 1. Is the Verifier registered in the Trust List (signed by a federation member)?
	entry, pool, err := i.LookupVerifier(clientID)
	if err != nil {
		return err
	}
	fmt.Printf("✔ Verifier found in Trust List: %s (%s)\n", entry.Name, entry.ClientID)

	// 2. Fetch the request object once (the verifier serves it a single time) and hand it to the
	//    vcknots presenter by value; the presenter verifies its x5c against the Trust List cert.
	if ru := q.Get("request_uri"); ru != "" {
		requestObject, err := fetchText(ru)
		if err != nil {
			return fmt.Errorf("fetch request object: %w", err)
		}
		requestURI = "openid4vp:?" + url.Values{"client_id": {clientID}, "request": {requestObject}}.Encode()
		if len(claims) == 0 {
			if claims, err = requestedClaims(requestObject); err != nil {
				return err
			}
		}
	}
	w, err := i.newWallet(&oid4vpRoots{pool: pool})
	if err != nil {
		return err
	}
	claims, err = availableClaims(w, claims)
	if err != nil {
		return err
	}
	fmt.Printf("  disclosing: %s\n", strings.Join(claims, ", "))

	// 3. Wallet Attestation is sent along with the direct_post response
	if err := i.EnsureAttestation(); err != nil {
		return err
	}
	installAttestationTransport(i)

	// vcknots verifies the request object x5c against the certificate from the Trust List
	redirect, err := w.PresentCredential(requestURI, i.holderKey, &sdjwtvc.SdJwtVcPresentationOptions{
		SelectedClaims:    claims,
		RequireKeyBinding: true,
	})
	if err != nil {
		return fmt.Errorf("presentation failed: %w", err)
	}
	fmt.Println("✔ Presentation accepted by the Verifier")
	if redirect != "" {
		fmt.Printf("  result: %s\n", redirect)
	}
	return nil
}

// requestedClaims reads the DCQL query from the request object to pre-select the claims to
// disclose. The signature is verified afterwards by the vcknots presenter.
func requestedClaims(requestObject string) ([]string, error) {
	jws, err := jose.ParseSigned(requestObject, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return nil, err
	}
	var ro struct {
		DCQL struct {
			Credentials []struct {
				Claims []struct {
					Path []any `json:"path"`
				} `json:"claims"`
			} `json:"credentials"`
		} `json:"dcql_query"`
	}
	if err := json.Unmarshal(jws.UnsafePayloadWithoutVerification(), &ro); err != nil {
		return nil, err
	}
	var out []string
	for _, c := range ro.DCQL.Credentials {
		for _, cl := range c.Claims {
			if len(cl.Path) > 0 {
				if s, ok := cl.Path[0].(string); ok {
					out = append(out, s)
				}
			}
		}
	}
	return out, nil
}

func latestCredential(w *wallet.Wallet) (*wallet.SavedCredential, error) {
	entries, _, err := w.GetCredentialEntries(wallet.GetCredentialEntriesRequest{})
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("no credentials in the wallet")
	}
	sort.Slice(entries, func(a, b int) bool { return entries[a].Entry.ReceivedAt.After(entries[b].Entry.ReceivedAt) })
	return entries[0], nil
}

// availableClaims keeps only claims that exist as disclosures in the latest credential.
func availableClaims(w *wallet.Wallet, wanted []string) ([]string, error) {
	latest, err := latestCredential(w)
	if err != nil {
		return nil, err
	}
	_, disclosures := decodeSDJWT(latest.Entry.Raw)
	var out []string
	for _, c := range wanted {
		if _, ok := disclosures[c]; ok {
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("the latest credential has none of the requested claims %v", wanted)
	}
	return out, nil
}

// ---- list --------------------------------------------------------------------------------------

func (i *Instance) list() error {
	w, err := i.newWallet(nil)
	if err != nil {
		return err
	}
	entries, total, err := w.GetCredentialEntries(wallet.GetCredentialEntriesRequest{})
	if err != nil {
		return err
	}
	fmt.Printf("%d credential(s)\n", total)
	for _, e := range entries {
		fmt.Printf("\n- %s (%s, received %s)\n", e.Entry.Id, e.Entry.MimeType, e.Entry.ReceivedAt.Format("2006-01-02 15:04:05"))
		printCredential(e.Entry.Raw)
		payload, _ := decodeSDJWT(e.Entry.Raw)
		if st, err := i.CheckStatus(payload); err != nil {
			fmt.Printf("  %-24s ? (%v)\n", "[Token Status List]", err)
		} else {
			fmt.Printf("  %-24s %s (idx=%d, Status Issuer: %s)\n", "[Token Status List]", StatusTypeName(st.Status), st.Idx, strings.Join(st.ChainPath, " -> "))
		}
	}
	return nil
}

func decodeSDJWT(raw []byte) (map[string]any, map[string]any) {
	cf := sdjwtvc.ParseCombinedFormatForPresentation(string(raw))
	payload := map[string]any{}
	if parts := strings.Split(cf.SDJWT, "."); len(parts) == 3 {
		if b, err := base64.RawURLEncoding.DecodeString(parts[1]); err == nil {
			_ = json.Unmarshal(b, &payload)
		}
	}
	disclosures := map[string]any{}
	for _, d := range cf.Disclosures {
		b, err := base64.RawURLEncoding.DecodeString(d)
		if err != nil {
			continue
		}
		var arr []any
		if json.Unmarshal(b, &arr) == nil && len(arr) == 3 {
			if name, ok := arr[1].(string); ok {
				disclosures[name] = arr[2]
			}
		}
	}
	return payload, disclosures
}

func printCredential(raw []byte) {
	payload, disclosures := decodeSDJWT(raw)
	fmt.Printf("  iss: %v\n  vct: %v\n  status: %v\n", payload["iss"], payload["vct"], toJSON(payload["status"]))
	keys := make([]string, 0, len(disclosures))
	for k := range disclosures {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Printf("  %-24s %s\n", k, toJSON(disclosures[k]))
	}
}

func toJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
