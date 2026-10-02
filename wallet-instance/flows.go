package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/credstore"
	"github.com/trustknots/vcknots/wallet/credstore/plugins/local"
	"github.com/trustknots/vcknots/wallet/presenter"
	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp"
	"github.com/trustknots/vcknots/wallet/receiver"
	"github.com/trustknots/vcknots/wallet/serializer/plugins/sdjwtvc"
)

type oid4vpRoots struct{ pool *x509.CertPool }

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

// ResetCredentials deletes all stored credentials (demo convenience).
func (i *Instance) ResetCredentials() error {
	err := os.Remove(filepath.Join(i.dir, "credstore.db"))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	i.info(M("保存済みクレデンシャルを削除", "Deleted the stored credentials"), Msg{})
	return nil
}

// ---- issuer metadata (display names) -----------------------------------------------------------

// credentialDisplay holds display information from the issuer metadata, per language ("ja", "en").
type credentialDisplay struct {
	Names       map[string]string
	Background  string
	TextColor   string
	ClaimLabels map[string]map[string]string // lang -> claim -> label
	IssuerNames map[string]string
	vct         string
}

// localeLang maps a BCP 47 locale to the UI language ("ja", "en"), or "" for others.
func localeLang(locale string) string {
	switch {
	case strings.HasPrefix(locale, "ja"):
		return "ja"
	case strings.HasPrefix(locale, "en"):
		return "en"
	}
	return ""
}

// pickLang returns the entry for lang, falling back to the other language.
func pickLang(m map[string]string, lang string) string {
	if v := m[lang]; v != "" {
		return v
	}
	for _, l := range []string{"ja", "en"} {
		if v := m[l]; v != "" {
			return v
		}
	}
	return ""
}

// NameIn returns the credential display name in lang.
func (d credentialDisplay) NameIn(lang string) string {
	if n := pickLang(d.Names, lang); n != "" {
		return n
	}
	return d.vct
}

// IssuerNameIn returns the issuer display name in lang.
func (d credentialDisplay) IssuerNameIn(lang string) string { return pickLang(d.IssuerNames, lang) }

// LabelIn returns the display label of a claim in lang.
func (d credentialDisplay) LabelIn(lang, claim string) string {
	if l := d.ClaimLabels[lang][claim]; l != "" {
		return l
	}
	for _, other := range []string{"ja", "en"} {
		if l := d.ClaimLabels[other][claim]; l != "" {
			return l
		}
	}
	return claim
}

var displayCache sync.Map

// displayFor returns display information for a credential type from the issuer metadata.
func displayFor(issuer, vct, configurationID string) credentialDisplay {
	key := issuer + "|" + vct + "|" + configurationID
	if v, ok := displayCache.Load(key); ok {
		return v.(credentialDisplay)
	}
	d := credentialDisplay{
		vct: vct, Names: map[string]string{}, IssuerNames: map[string]string{},
		ClaimLabels: map[string]map[string]string{"ja": {}, "en": {}}, Background: "#155e86", TextColor: "#ffffff",
	}
	raw, err := fetchText(strings.TrimSuffix(issuer, "/") + "/.well-known/openid-credential-issuer")
	if err == nil {
		var md struct {
			Display []struct {
				Name   string `json:"name"`
				Locale string `json:"locale"`
			} `json:"display"`
			Configs map[string]struct {
				Vct      string `json:"vct"`
				Metadata struct {
					Display []struct {
						Name       string `json:"name"`
						Locale     string `json:"locale"`
						Background string `json:"background_color"`
						TextColor  string `json:"text_color"`
					} `json:"display"`
					Claims []struct {
						Path    []any `json:"path"`
						Display []struct {
							Name   string `json:"name"`
							Locale string `json:"locale"`
						} `json:"display"`
					} `json:"claims"`
				} `json:"credential_metadata"`
			} `json:"credential_configurations_supported"`
		}
		if json.Unmarshal([]byte(raw), &md) == nil {
			for _, dd := range md.Display {
				if l := localeLang(dd.Locale); l != "" {
					d.IssuerNames[l] = dd.Name
				}
			}
			for id, c := range md.Configs {
				if (configurationID != "" && id == configurationID) || (vct != "" && c.Vct == vct) {
					for n, dd := range c.Metadata.Display {
						if l := localeLang(dd.Locale); l != "" {
							d.Names[l] = dd.Name
						} else if n == 0 {
							d.Names["ja"] = dd.Name
						}
						if dd.Background != "" {
							d.Background = dd.Background
						}
						if dd.TextColor != "" {
							d.TextColor = dd.TextColor
						}
					}
					for _, cl := range c.Metadata.Claims {
						name, ok := "", false
						if len(cl.Path) > 0 {
							name, ok = cl.Path[0].(string)
						}
						if !ok {
							continue
						}
						for n, cd := range cl.Display {
							if l := localeLang(cd.Locale); l != "" {
								d.ClaimLabels[l][name] = cd.Name
							} else if n == 0 {
								d.ClaimLabels["ja"][name] = cd.Name
							}
						}
					}
				}
			}
		}
	}
	displayCache.Store(key, d)
	return d
}

// ---- receive -----------------------------------------------------------------------------------

// OfferPreview is a parsed and checked Credential Offer, before the user accepts it.
type OfferPreview struct {
	OfferURI        string
	Issuer          string
	ConfigurationID []string
	IssuerChain     []string
	Display         credentialDisplay
	Offer           *wallet.CredentialOffer
}

// PreviewOffer parses a Credential Offer and checks that the issuer is a federation member.
func (i *Instance) PreviewOffer(offerURI string) (*OfferPreview, error) {
	parsed, err := url.Parse(strings.TrimSpace(offerURI))
	if err != nil {
		return nil, i.fail(M("Credential Offer を解析できません", "Cannot parse the Credential Offer"), err)
	}
	var offerJSON struct {
		CredentialIssuer           string                                  `json:"credential_issuer"`
		CredentialConfigurationIDs []string                                `json:"credential_configuration_ids"`
		Grants                     map[string]*wallet.CredentialOfferGrant `json:"grants"`
	}
	if err := json.Unmarshal([]byte(parsed.Query().Get("credential_offer")), &offerJSON); err != nil {
		return nil, i.fail(M("Credential Offer を解析できません", "Cannot parse the Credential Offer"), fmt.Errorf("invalid credential offer: %w", err))
	}
	i.info(M("Credential Offer を受信", "Received a Credential Offer"), S("issuer %s, %s", offerJSON.CredentialIssuer, strings.Join(offerJSON.CredentialConfigurationIDs, ", ")))

	// Is the issuer a member of the federation (openid_credential_issuer)?
	chain, _, err := ResolveEntityType(offerJSON.CredentialIssuer, "openid_credential_issuer", i.trustAnchor)
	if err != nil {
		return nil, i.fail(M("Issuer を信頼できません", "Cannot trust the Issuer"), fmt.Errorf("issuer is not trusted: %w", err))
	}
	i.ok(M("Issuer を OpenID Federation で確認", "Issuer verified through OpenID Federation"), S("%s", strings.Join(chain.Path, " → ")))
	issuerURL, err := url.Parse(offerJSON.CredentialIssuer)
	if err != nil {
		return nil, err
	}
	cfg := ""
	if len(offerJSON.CredentialConfigurationIDs) > 0 {
		cfg = offerJSON.CredentialConfigurationIDs[0]
	}
	return &OfferPreview{
		OfferURI:        offerURI,
		Issuer:          offerJSON.CredentialIssuer,
		ConfigurationID: offerJSON.CredentialConfigurationIDs,
		IssuerChain:     chain.Path,
		Display:         displayFor(offerJSON.CredentialIssuer, "", cfg),
		Offer: &wallet.CredentialOffer{
			CredentialIssuer:           issuerURL,
			CredentialConfigurationIDs: offerJSON.CredentialConfigurationIDs,
			Grants:                     offerJSON.Grants,
		},
	}, nil
}

// AcceptOffer runs OID4VCI (pre-authorized code) with the Wallet Attestation and stores the credential.
func (i *Instance) AcceptOffer(p *OfferPreview) (*wallet.SavedCredential, error) {
	if err := i.EnsureAttestation(); err != nil {
		return nil, err
	}
	installAttestationTransport(i)
	w, err := i.newWallet(nil)
	if err != nil {
		return nil, err
	}
	saved, err := w.ReceiveCredential(wallet.ReceiveCredentialRequest{
		CredentialOffer: p.Offer,
		Type:            receiver.Oid4vci,
		Key:             i.holderKey,
		RequestedFormat: credential.SDJwtVC,
	})
	if err != nil {
		return nil, i.fail(M("クレデンシャルの受け取りに失敗", "Failed to receive the credential"), fmt.Errorf("receive failed: %w", err))
	}
	i.ok(M("クレデンシャルを受け取り保存 (vcknots OID4VCI)", "Received and stored the credential (vcknots OID4VCI)"),
		M(fmt.Sprintf("%s (%s)", p.Display.NameIn("ja"), saved.Entry.Id), fmt.Sprintf("%s (%s)", p.Display.NameIn("en"), saved.Entry.Id)))
	return saved, nil
}

// ---- present -----------------------------------------------------------------------------------

// PresentationPrep is an authenticated presentation request, before the user consents.
type PresentationPrep struct {
	ClientID       string
	RequestObject  string
	RequestByValue string
	LoTE           *LoadedLoTE
	RP             *RelyingParty
	Requested      []string
	ClaimOrder     []string // requested claims first, then the other disclosable ones
	Credential     *CredentialView
	CreatedAt      time.Time
}

// PreparePresentation authenticates the Relying Party (LoTE + access certificate) and works out
// which claims are requested.
func (i *Instance) PreparePresentation(requestURI string) (*PresentationPrep, error) {
	parsed, err := url.Parse(strings.TrimSpace(requestURI))
	if err != nil {
		return nil, i.fail(M("提示リクエストを解析できません", "Cannot parse the presentation request"), err)
	}
	q := parsed.Query()
	clientID := q.Get("client_id")
	if clientID == "" {
		return nil, i.fail(M("提示リクエストを解析できません", "Cannot parse the presentation request"), fmt.Errorf("client_id missing in authorization request"))
	}
	i.info(M("提示リクエストを受信", "Received a presentation request"), S("client_id %s", clientID))

	// 1. Trust anchors of the Access CAs from the WRPAC Providers LoTE (signer trusted via federation)
	lote, err := i.LoadWRPACProvidersLoTE()
	if err != nil {
		return nil, i.fail(M("Trust List (LoTE) を検証できません", "Cannot validate the Trust List (LoTE)"), err)
	}
	signer := strings.Join(lote.FederationPath, " → ")
	i.ok(M("Trust List (ETSI TS 119 602 LoTE) を検証", "Validated the Trust List (ETSI TS 119 602 LoTE)"),
		M(fmt.Sprintf("seq %d, %s, 署名者を OpenID Federation で確認: %s", lote.SequenceNumber, lote.SchemeOperator, signer),
			fmt.Sprintf("seq %d, %s, signer verified through OpenID Federation: %s", lote.SequenceNumber, lote.SchemeOperator, signer)))

	// 2. Fetch the request object once (the verifier serves it a single time)
	ru := q.Get("request_uri")
	if ru == "" {
		return nil, i.fail(M("署名付きリクエストが必要です", "A signed request is required"), fmt.Errorf("a signed request object (request_uri) carrying the access certificate is required"))
	}
	requestObject, err := fetchText(ru)
	if err != nil {
		return nil, i.fail(M("リクエストオブジェクトを取得できません", "Cannot fetch the request object"), err)
	}

	// 3. Relying Party authentication with its access certificate (ETSI TS 119 411-8)
	rp, err := lote.AuthenticateRelyingParty(requestObject, clientID)
	if err != nil {
		return nil, i.fail(M("Relying Party を認証できません", "Cannot authenticate the Relying Party"), err)
	}
	i.ok(M("アクセス証明書 (WRPAC) を LoTE のトラストアンカーまで検証", "Validated the access certificate (WRPAC) up to the LoTE trust anchor"),
		M(fmt.Sprintf("%s / %s (%s), policy %s, 発行 %s", rp.Organization, rp.CommonName, rp.OrganizationIdentifier, rp.Policy, rp.AccessCA),
			fmt.Sprintf("%s / %s (%s), policy %s, issued by %s", rp.Organization, rp.CommonName, rp.OrganizationIdentifier, rp.Policy, rp.AccessCA)))

	requested, err := requestedClaims(requestObject)
	if err != nil {
		return nil, err
	}
	creds, err := i.Credentials(false)
	if err != nil {
		return nil, err
	}
	if len(creds) == 0 {
		return nil, i.fail(M("提示できるクレデンシャルがありません", "No credential to present"), fmt.Errorf("no credentials in the wallet"))
	}
	order := []string{}
	for _, c := range requested {
		if _, ok := creds[0].Disclosures[c]; ok {
			order = append(order, c)
		}
	}
	for _, c := range creds[0].ClaimNames {
		if !slices.Contains(order, c) {
			order = append(order, c)
		}
	}
	return &PresentationPrep{
		ClaimOrder:     order,
		ClientID:       clientID,
		RequestObject:  requestObject,
		RequestByValue: "openid4vp:?" + url.Values{"client_id": {clientID}, "request": {requestObject}}.Encode(),
		LoTE:           lote,
		RP:             rp,
		Requested:      requested,
		Credential:     creds[0],
		CreatedAt:      time.Now(),
	}, nil
}

// SubmitPresentation creates the SD-JWT VC presentation with the chosen disclosures + KB-JWT and
// posts it (with the Wallet Attestation) to the verifier.
func (i *Instance) SubmitPresentation(p *PresentationPrep, claims []string) (string, error) {
	var selected []string
	for _, c := range claims {
		if _, ok := p.Credential.Disclosures[c]; ok {
			selected = append(selected, c)
		}
	}
	if len(selected) == 0 {
		return "", i.fail(M("開示する属性がありません", "No attributes selected for disclosure"), fmt.Errorf("no claims selected"))
	}
	i.info(M("選択的開示", "Selective disclosure"), S("%s", strings.Join(selected, ", ")))
	if err := i.EnsureAttestation(); err != nil {
		return "", err
	}
	installAttestationTransport(i)
	w, err := i.newWallet(&oid4vpRoots{pool: p.LoTE.Pool()})
	if err != nil {
		return "", err
	}
	// vcknots verifies the request object signature, the x5c path to the LoTE trust anchors and the
	// revocation status of the access certificate (CRL distribution point)
	redirect, err := w.PresentCredential(p.RequestByValue, i.holderKey, &sdjwtvc.SdJwtVcPresentationOptions{
		SelectedClaims:    selected,
		RequireKeyBinding: true,
	})
	if err != nil {
		if strings.Contains(err.Error(), "certificate was revoked") {
			return "", i.fail(M("アクセス証明書が失効しています (Access CA の CRL)", "The access certificate is revoked (Access CA CRL)"), err)
		}
		return "", i.fail(M("提示に失敗", "Presentation failed"), err)
	}
	i.ok(M("Verifier が提示を受理 (vcknots OID4VP, SD-JWT VC + KB-JWT)", "The Verifier accepted the presentation (vcknots OID4VP, SD-JWT VC + KB-JWT)"), S("%s", redirect))
	return redirect, nil
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

// ---- stored credentials ------------------------------------------------------------------------

// CredentialView is a stored credential decoded for display.
type CredentialView struct {
	ID          string
	ReceivedAt  time.Time
	Issuer      string
	Vct         string
	Payload     map[string]any
	Disclosures map[string]any
	ClaimNames  []string
	Display     credentialDisplay
	Status      *StatusResult
	StatusErr   string
}

func (c *CredentialView) Value(claim string) string {
	switch v := c.Disclosures[claim].(type) {
	case string:
		return v
	default:
		return toJSON(v)
	}
}

// Credentials returns the stored credentials, newest first, optionally with their status.
func (i *Instance) Credentials(withStatus bool) ([]*CredentialView, error) {
	w, err := i.newWallet(nil)
	if err != nil {
		return nil, err
	}
	entries, _, err := w.GetCredentialEntries(wallet.GetCredentialEntriesRequest{})
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(a, b int) bool { return entries[a].Entry.ReceivedAt.After(entries[b].Entry.ReceivedAt) })
	out := make([]*CredentialView, 0, len(entries))
	for _, e := range entries {
		payload, disclosures := decodeSDJWT(e.Entry.Raw)
		v := &CredentialView{ID: e.Entry.Id, ReceivedAt: e.Entry.ReceivedAt, Payload: payload, Disclosures: disclosures}
		v.Issuer, _ = payload["iss"].(string)
		v.Vct, _ = payload["vct"].(string)
		for k := range disclosures {
			v.ClaimNames = append(v.ClaimNames, k)
		}
		sort.Strings(v.ClaimNames)
		v.Display = displayFor(v.Issuer, v.Vct, "")
		if withStatus {
			if st, err := i.CheckStatus(payload); err != nil {
				v.StatusErr = err.Error()
			} else {
				v.Status = st
			}
		}
		out = append(out, v)
	}
	return out, nil
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

func toJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
