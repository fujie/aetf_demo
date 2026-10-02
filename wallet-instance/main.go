// Command wallet-instance is the Wallet Instance (Holder) of the IHV prototype.
//
// It is built on the vcknots Go wallet library (OID4VCI / OID4VP, SD-JWT VC) and adds:
//   - Wallet Attestation obtained from the Wallet Provider (trusted via OpenID Federation)
//     and presented to the Issuer / Verifier as attestation-based client authentication
//   - Issuer trust check via OpenID Federation before accepting a Credential Offer
//   - Relying Party authentication with the WRPAC Providers LoTE (ETSI TS 119 602) and
//     access certificates (ETSI TS 119 411-8)
//   - Token Status List checks of stored credentials
//
// It runs as a CLI or, with `serve`, as a web wallet UI.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/trustknots/vcknots/wallet/env"
)

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// basePort mirrors BASE_PORT of the TypeScript servers (src/config.ts).
func basePort() int {
	if p, err := strconv.Atoi(os.Getenv("BASE_PORT")); err == nil && p > 0 {
		return p
	}
	return 8700
}

func usage() {
	fmt.Fprintf(os.Stderr, `usage: wallet-instance <command> [args]

commands:
  serve                        run the web wallet UI (default http://localhost:<BASE_PORT+60>)
  init                         register with the Wallet Provider and obtain a Wallet Attestation
  receive '<credential offer>' receive a credential (OID4VCI pre-authorized code flow)
  present '<openid4vp uri>' [--claims a,b,c]
                               present the latest credential (OID4VP, SD-JWT VC + KB-JWT)
  list                         list stored credentials (with Token Status List status)

environment:
  WALLET_DIR       wallet data directory (default ./.wallet)
  TRUST_ANCHOR     trust anchor config  (default ../.data/trust-anchor.json)
  BASE_PORT        base port of the prototype servers (default 8700)
  WALLET_PROVIDER  Wallet Provider entity id (default http://localhost:<BASE_PORT+30>)
  TRUST_LIST       Trust List provider entity id (default http://localhost:<BASE_PORT+31>)
  WALLET_UI_PORT   port of the web wallet UI (default BASE_PORT+60)
  DEMO_CONSOLE     demo console URL to forward wallet events to (optional)
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
		inst.state.WalletProvider = getenv("WALLET_PROVIDER", fmt.Sprintf("http://localhost:%d", basePort()+30))
		inst.state.TrustListProvider = getenv("TRUST_LIST", fmt.Sprintf("http://localhost:%d", basePort()+31))
		inst.steps.console = true
		switch os.Args[1] {
		case "serve":
			if e := inst.EnsureRegistered(); e != nil {
				fmt.Fprintf(os.Stderr, "warning: could not confirm the Wallet Instance registration: %s\n", Humanize(e.Error(), cliLang()))
			}
			err = inst.serve(getenv("WALLET_UI_PORT", strconv.Itoa(basePort()+60)))
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
		fmt.Fprintf(os.Stderr, "✘ %s\n", Humanize(err.Error(), cliLang()))
		os.Exit(1)
	}
}

func (i *Instance) receive(offerURI string) error {
	preview, err := i.PreviewOffer(offerURI)
	if err != nil {
		return err
	}
	saved, err := i.AcceptOffer(preview)
	if err != nil {
		return err
	}
	creds, err := i.Credentials(false)
	if err != nil {
		return err
	}
	for _, c := range creds {
		if c.ID == saved.Entry.Id {
			printCredential(c)
		}
	}
	return nil
}

func (i *Instance) present(requestURI string, claims []string) error {
	prep, err := i.PreparePresentation(requestURI)
	if err != nil {
		return err
	}
	if len(claims) == 0 {
		claims = prep.Requested
	}
	_, err = i.SubmitPresentation(prep, claims)
	return err
}

func (i *Instance) list() error {
	creds, err := i.Credentials(true)
	if err != nil {
		return err
	}
	fmt.Printf("%d credential(s)\n", len(creds))
	for _, c := range creds {
		fmt.Printf("\n- %s: %s (received %s)\n", c.ID, c.Display.NameIn(cliLang()), c.ReceivedAt.Format("2006-01-02 15:04:05"))
		printCredential(c)
		if c.Status != nil {
			fmt.Printf("  %-24s %s (idx=%d, Status Issuer: %s)\n", "[Token Status List]", StatusTypeName(c.Status.Status), c.Status.Idx, strings.Join(c.Status.ChainPath, " -> "))
		} else {
			fmt.Printf("  %-24s ? (%s)\n", "[Token Status List]", c.StatusErr)
		}
	}
	return nil
}

func printCredential(c *CredentialView) {
	fmt.Printf("  iss: %v\n  vct: %v\n  status: %v\n", c.Issuer, c.Vct, toJSON(c.Payload["status"]))
	for _, k := range c.ClaimNames {
		fmt.Printf("  %-24s %s\n", k, toJSON(c.Disclosures[k]))
	}
}
