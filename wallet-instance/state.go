package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/go-jose/go-jose/v4"
)

// KeyEntry is a persisted P-256 key implementing wallet.IKeyEntry.
type KeyEntry struct {
	id   string
	priv *ecdsa.PrivateKey
}

func (k *KeyEntry) ID() string { return k.id }

func (k *KeyEntry) PublicKey() jose.JSONWebKey {
	return jose.JSONWebKey{Key: &k.priv.PublicKey, Algorithm: string(jose.ES256), Use: "sig"}
}

// Sign returns an IEEE P1363 (R||S) ES256 signature.
func (k *KeyEntry) Sign(data []byte) ([]byte, error) {
	hash := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, k.priv, hash[:])
	if err != nil {
		return nil, err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return sig, nil
}

func loadOrCreateKey(path, id string) (*KeyEntry, error) {
	if raw, err := os.ReadFile(path); err == nil {
		var jwk jose.JSONWebKey
		if err := jwk.UnmarshalJSON(raw); err != nil {
			return nil, err
		}
		priv, ok := jwk.Key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%s is not an EC private key", path)
		}
		return &KeyEntry{id: id, priv: priv}, nil
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	raw, err := (jose.JSONWebKey{Key: priv, Algorithm: string(jose.ES256)}).MarshalJSON()
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return nil, err
	}
	return &KeyEntry{id: id, priv: priv}, nil
}

// State is the Wallet Instance's persisted state.
type State struct {
	WalletProvider    string `json:"wallet_provider"`
	TrustListProvider string `json:"trust_list_provider"`
	WalletInstanceID  string `json:"wallet_instance_id,omitempty"`
	WalletAttestation string `json:"wallet_attestation,omitempty"`
}

type Instance struct {
	dir         string
	state       State
	trustAnchor TrustAnchor
	// instanceKey is bound to the Wallet Attestation (cnf.jwk); holderKey binds credentials.
	instanceKey *KeyEntry
	holderKey   *KeyEntry

	reRegistered bool
}

func openInstance(dir, trustAnchorPath string) (*Instance, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	inst := &Instance{dir: dir}
	raw, err := os.ReadFile(trustAnchorPath)
	if err != nil {
		return nil, fmt.Errorf("trust anchor config: %w (start the servers first: npm start)", err)
	}
	if err := json.Unmarshal(raw, &inst.trustAnchor); err != nil {
		return nil, fmt.Errorf("trust anchor config: %w", err)
	}
	if raw, err := os.ReadFile(filepath.Join(dir, "state.json")); err == nil {
		if err := json.Unmarshal(raw, &inst.state); err != nil {
			return nil, err
		}
	}
	if inst.instanceKey, err = loadOrCreateKey(filepath.Join(dir, "instance-key.jwk"), "wallet-instance-key"); err != nil {
		return nil, err
	}
	if inst.holderKey, err = loadOrCreateKey(filepath.Join(dir, "holder-key.jwk"), "holder-key"); err != nil {
		return nil, err
	}
	return inst, nil
}

func (i *Instance) save() error {
	raw, err := json.MarshalIndent(i.state, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(i.dir, "state.json"), raw, 0o600)
}
