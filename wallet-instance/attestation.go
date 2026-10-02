package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
)

const (
	attestationTyp        = "oauth-client-attestation+jwt"
	attestationPopTyp     = "oauth-client-attestation-pop+jwt"
	attestationRequestTyp = "wallet-attestation-request+jwt"
	headerAttestation     = "OAuth-Client-Attestation"
	headerAttestationPoP  = "OAuth-Client-Attestation-PoP"
)

func signJWT(key *KeyEntry, typ string, claims any) (string, error) {
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: key.priv},
		(&jose.SignerOptions{}).WithType(jose.ContentType(typ)),
	)
	if err != nil {
		return "", err
	}
	return jwt.Signed(signer).Claims(claims).Serialize()
}

func postJSON(u string, body any, out any) error {
	raw, _ := json.Marshal(body)
	resp, err := http.Post(u, "application/json", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("POST %s -> %d: %s", u, resp.StatusCode, string(data))
	}
	return json.Unmarshal(data, out)
}

// walletProviderMetadata resolves the Wallet Provider via OpenID Federation.
func (i *Instance) walletProviderMetadata() (*ResolvedChain, map[string]any, error) {
	return ResolveEntityType(i.state.WalletProvider, "wallet_provider", i.trustAnchor)
}

// walletProviderAPI is the Wallet Provider's public API metadata (/.well-known/wallet-provider).
// The endpoints are not part of the federation metadata; the federation only vouches for the
// Wallet Provider and its attestation signing key.
type walletProviderAPI struct {
	WalletProvider               string `json:"wallet_provider"`
	InstanceRegistrationEndpoint string `json:"wallet_instance_registration_endpoint"`
	AttestationEndpoint          string `json:"wallet_attestation_endpoint"`
}

func (i *Instance) walletProviderEndpoints() (*walletProviderAPI, error) {
	raw, err := fetchText(strings.TrimSuffix(i.state.WalletProvider, "/") + "/.well-known/wallet-provider")
	if err != nil {
		return nil, fmt.Errorf("wallet provider metadata: %w", err)
	}
	var api walletProviderAPI
	if err := json.Unmarshal([]byte(raw), &api); err != nil {
		return nil, fmt.Errorf("wallet provider metadata: %w", err)
	}
	// the metadata must describe the entity whose Trust Chain was validated
	if api.WalletProvider != i.state.WalletProvider {
		return nil, fmt.Errorf("wallet provider metadata is for %q, not %q", api.WalletProvider, i.state.WalletProvider)
	}
	if api.InstanceRegistrationEndpoint == "" || api.AttestationEndpoint == "" {
		return nil, fmt.Errorf("wallet provider metadata lacks endpoints")
	}
	return &api, nil
}

// Register registers this Wallet Instance with the Wallet Provider (red "Registration" arrow).
func (i *Instance) Register() error {
	chain, _, err := i.walletProviderMetadata()
	if err != nil {
		return i.fail(M("Wallet Provider を信頼できません", "Cannot trust the Wallet Provider"), fmt.Errorf("wallet provider is not trusted: %w", err))
	}
	i.ok(M("Wallet Provider を OpenID Federation で確認", "Wallet Provider verified through OpenID Federation"), S("%s", strings.Join(chain.Path, " → ")))
	api, err := i.walletProviderEndpoints()
	if err != nil {
		return i.fail(M("Wallet Provider のメタデータを取得できません", "Cannot fetch the Wallet Provider metadata"), err)
	}
	endpoint := api.InstanceRegistrationEndpoint
	pub := i.instanceKey.PublicKey()
	var res struct {
		WalletInstanceID string `json:"wallet_instance_id"`
	}
	if err := postJSON(endpoint, map[string]any{"jwk": pub}, &res); err != nil {
		return err
	}
	i.state.WalletInstanceID = res.WalletInstanceID
	i.ok(M("Wallet Provider に Wallet Instance を登録", "Registered the Wallet Instance with the Wallet Provider"), S("%s", res.WalletInstanceID))
	return i.save()
}

// EnsureRegistered confirms that the Wallet Provider still knows this Wallet Instance (the
// registration is idempotent per instance key) and adopts the ID it returns. A registration lost
// on the Wallet Provider side is restored, and an attestation bound to an old ID is dropped.
func (i *Instance) EnsureRegistered() error {
	if i.state.WalletInstanceID == "" {
		return nil
	}
	prev := i.state.WalletInstanceID
	if err := i.Register(); err != nil {
		return err
	}
	if i.state.WalletInstanceID != prev {
		i.state.WalletAttestation = ""
		i.info(M("Wallet Provider に再登録", "Re-registered with the Wallet Provider"),
			M(fmt.Sprintf("以前の登録 %s が見つからないため新しい ID で登録しました", prev), fmt.Sprintf("The previous registration %s was not found, so a new ID was registered", prev)))
		return i.save()
	}
	return nil
}

// RefreshAttestation obtains a new Wallet Attestation and verifies it with the WP key from the federation.
func (i *Instance) RefreshAttestation() error {
	if i.state.WalletInstanceID == "" {
		if err := i.Register(); err != nil {
			return err
		}
	}
	_, md, err := i.walletProviderMetadata()
	if err != nil {
		return err
	}
	api, err := i.walletProviderEndpoints()
	if err != nil {
		return i.fail(M("Wallet Provider のメタデータを取得できません", "Cannot fetch the Wallet Provider metadata"), err)
	}
	endpoint := api.AttestationEndpoint
	now := time.Now()
	req, err := signJWT(i.instanceKey, attestationRequestTyp, map[string]any{
		"iss": i.state.WalletInstanceID,
		"aud": i.state.WalletProvider,
		"iat": now.Unix(),
		"exp": now.Add(2 * time.Minute).Unix(),
		"jti": uuid.NewString(),
	})
	if err != nil {
		return err
	}
	var res struct {
		WalletAttestation string `json:"wallet_attestation"`
	}
	if err := postJSON(endpoint, map[string]any{"request": req}, &res); err != nil {
		// The Wallet Provider no longer knows this instance (e.g. its data was reset): re-register.
		if strings.Contains(err.Error(), "unknown wallet instance") && !i.reRegistered {
			i.reRegistered = true
			i.state.WalletInstanceID = ""
			return i.RefreshAttestation()
		}
		// a revoked / unknown instance must not keep using its previous attestation
		i.state.WalletAttestation = ""
		_ = i.save()
		return i.fail(M("Wallet Attestation の取得に失敗", "Failed to obtain a Wallet Attestation"), err)
	}
	jwks, err := JWKSFromMetadata(md)
	if err != nil {
		return err
	}
	if _, err := verifyJWS(res.WalletAttestation, jwks, attestationTyp); err != nil {
		return fmt.Errorf("received wallet attestation is invalid: %w", err)
	}
	i.state.WalletAttestation = res.WalletAttestation
	exp := i.AttestationExpiry().Format("15:04:05")
	i.ok(M("Wallet Attestation を取得", "Obtained a Wallet Attestation"),
		M("Wallet Provider の鍵 (Federation メタデータ) で署名を確認、有効期限 "+exp, "Signature verified with the Wallet Provider key (federation metadata), expires "+exp))
	return i.save()
}

// EnsureAttestation refreshes the attestation if missing or about to expire.
func (i *Instance) EnsureAttestation() error {
	if i.state.WalletAttestation != "" {
		if tok, err := jwt.ParseSigned(i.state.WalletAttestation, []jose.SignatureAlgorithm{jose.ES256}); err == nil {
			var c jwt.Claims
			var extra struct {
				Status map[string]any `json:"status"`
			}
			// attestations issued before the Wallet Provider published revocation status (no
			// `status` claim) are re-fetched, since Issuers / Verifiers require it
			if tok.UnsafeClaimsWithoutVerification(&c, &extra) == nil && c.Expiry != nil &&
				c.Expiry.Time().After(time.Now().Add(time.Minute)) && extra.Status != nil {
				// The Wallet Provider may have suspended, revoked or re-activated this instance:
				// check the Status List entry referenced by the cached attestation.
				st, err := i.AttestationStatus()
				if err == nil && st.Status == 0 {
					return nil
				}
				if err == nil {
					i.info(M("保持中の Wallet Attestation が無効", "The held Wallet Attestation is not valid"),
						M(fmt.Sprintf("Status List idx %d = %s のため再取得します", st.Idx, StatusTypeName(st.Status)), fmt.Sprintf("Status List idx %d = %s, fetching a new one", st.Idx, StatusTypeName(st.Status))))
				}
			}
		}
	}
	return i.RefreshAttestation()
}

// AttestationStatus checks the Token Status List entry referenced by the current Wallet
// Attestation, i.e. whether the Wallet Provider considers this Wallet Instance valid.
func (i *Instance) AttestationStatus() (*StatusResult, error) {
	if i.state.WalletAttestation == "" {
		return nil, fmt.Errorf("no wallet attestation")
	}
	parts := strings.Split(i.state.WalletAttestation, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid wallet attestation")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, err
	}
	return i.CheckStatus(payload)
}

// attestationTransport adds the Wallet Attestation + PoP headers (attestation-based client
// authentication) to form POSTs sent by the vcknots wallet library, i.e. the OID4VCI token
// request and the OID4VP direct_post response. The PoP audience is the target origin.
type attestationTransport struct {
	base http.RoundTripper
	inst *Instance
}

func (t *attestationTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method == http.MethodPost &&
		strings.HasPrefix(req.Header.Get("Content-Type"), "application/x-www-form-urlencoded") &&
		t.inst.state.WalletAttestation != "" {
		aud := req.URL.Scheme + "://" + req.URL.Host
		pop, err := signJWT(t.inst.instanceKey, attestationPopTyp, map[string]any{
			"iss": t.inst.state.WalletInstanceID,
			"aud": aud,
			"jti": uuid.NewString(),
			"iat": time.Now().Unix(),
		})
		if err != nil {
			return nil, err
		}
		req = req.Clone(req.Context())
		req.Header.Set(headerAttestation, t.inst.state.WalletAttestation)
		req.Header.Set(headerAttestationPoP, pop)
		t.inst.info(M("Wallet Attestation + PoP を付与して送信", "Sending with Wallet Attestation + PoP"), S("%s %s (PoP aud=%s)", req.Method, req.URL, aud))
	}
	return t.base.RoundTrip(req)
}

func installAttestationTransport(inst *Instance) {
	if _, done := http.DefaultTransport.(*attestationTransport); done {
		return
	}
	// The vcknots wallet uses http.Client values with a nil Transport, i.e. http.DefaultTransport.
	http.DefaultTransport = &attestationTransport{base: http.DefaultTransport, inst: inst}
}

// AttestationExpiry returns the expiry of the current Wallet Attestation (zero if none).
func (i *Instance) AttestationExpiry() time.Time {
	if i.state.WalletAttestation == "" {
		return time.Time{}
	}
	tok, err := jwt.ParseSigned(i.state.WalletAttestation, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return time.Time{}
	}
	var c jwt.Claims
	if tok.UnsafeClaimsWithoutVerification(&c) != nil || c.Expiry == nil {
		return time.Time{}
	}
	return c.Expiry.Time()
}
