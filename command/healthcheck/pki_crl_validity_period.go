package healthcheck

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	//"time"

	"github.com/hashicorp/vault/sdk/logical"

	"github.com/hashicorp/go-secure-stdlib/parseutil"
)

type CRLValidityPeriod struct {
	Enabled bool

	CRLExpiryPercentage      int
	DeltaCRLExpiryPercentage int

	UnsupportedVersion bool
	NoDeltas           bool

	CRLs      map[string]*x509.RevocationList
	DeltaCRLs map[string]*x509.RevocationList

	CRLConfig *PathFetch
}

func NewCRLValidityPeriodCheck() Check {
	return &CRLValidityPeriod{
		CRLs:      make(map[string]*x509.RevocationList),
		DeltaCRLs: make(map[string]*x509.RevocationList),
	}
}

func (h *CRLValidityPeriod) Name() string {
	return "crl_validity_period"
}

func (h *CRLValidityPeriod) IsEnabled() bool {
	return h.Enabled
}

func (h *CRLValidityPeriod) DefaultConfig() map[string]interface{} {
	return map[string]interface{}{
		"crl_expiry_pct_critical":       "95",
		"delta_crl_expiry_pct_critical": "95",
	}
}

func (h *CRLValidityPeriod) LoadConfig(config map[string]interface{}) error {
	value, err := parseutil.SafeParseIntRange(config["crl_expiry_pct_critical"], 1, 99)
	if err != nil {
		return fmt.Errorf("error parsing %v.crl_expiry_pct_critical: %w", h.Name(), err)
	}
	h.CRLExpiryPercentage = int(value)

	value, err = parseutil.SafeParseIntRange(config["delta_crl_expiry_pct_critical"], 1, 99)
	if err != nil {
		return fmt.Errorf("error parsing %v.delta_crl_expiry_pct_critical: %w", h.Name(), err)
	}
	h.DeltaCRLExpiryPercentage = int(value)

	enabled, err := parseutil.ParseBool(config["enabled"])
	if err != nil {
		return fmt.Errorf("error parsing %v.enabled: %w", h.Name(), err)
	}
	h.Enabled = enabled

	return nil
}

func (h *CRLValidityPeriod) FetchResources(e *Executor) error {
	if !h.Enabled {
		return nil
	}

	// Check if the issuers are fetched yet.
	issuersRet, err := e.FetchIfNotFetched(logical.ListOperation, "/{{mount}}/issuers")
	if err != nil {
		return err
	}

	if !issuersRet.IsSecretOK() {
		if issuersRet.IsUnsupportedPathError() {
			h.UnsupportedVersion = true
		}

		return nil
	}

	if len(issuersRet.ParsedCache) == 0 {
		var issuers []string
		for _, rawIssuerId := range issuersRet.Secret.Data["keys"].([]interface{}) {
			issuers = append(issuers, rawIssuerId.(string))
		}
		issuersRet.ParsedCache["issuers"] = issuers
	}

	for _, issuer := range issuersRet.ParsedCache["issuers"].([]string) {
		crlRet, err := e.FetchIfNotFetched(logical.ReadOperation, "/{{mount}}/issuer/"+issuer+"/crl")
		if err != nil {
			return err
		}

		if !crlRet.IsSecretOK() {
			if crlRet.IsUnsupportedPathError() {
				h.UnsupportedVersion = true
			}
			continue
		}

		if len(crlRet.ParsedCache) == 0 {
			// Need to parse out the issuer from its PEM format.
			pemBlock, _ := pem.Decode([]byte(crlRet.Secret.Data["crl"].(string)))
			if pemBlock == nil {
				return fmt.Errorf("failed to parse issuer's PEM: %v", issuer)
			}

			cert, err := x509.ParseRevocationList(pemBlock.Bytes)
			if err != nil {
				return fmt.Errorf("failed to parse certificate for issuer (%v): %w", issuer, err)
			}

			crlRet.ParsedCache["crl"] = cert
		}

		h.CRLs[issuer] = crlRet.ParsedCache["crl"].(*x509.RevocationList)

		deltaRet, err := e.FetchIfNotFetched(logical.ReadOperation, "/{{mount}}/issuer/"+issuer+"/crl/delta")
		if err != nil {
			return err
		}

		if !deltaRet.IsSecretOK() {
			if deltaRet.IsUnsupportedPathError() {
				h.NoDeltas = true
			}
			continue
		}

		if len(deltaRet.ParsedCache) == 0 {
			// Need to parse out the issuer from its PEM format.
			pemBlock, _ := pem.Decode([]byte(deltaRet.Secret.Data["crl"].(string)))
			if pemBlock == nil {
				return fmt.Errorf("failed to parse issuer's PEM: %v", issuer)
			}

			cert, err := x509.ParseRevocationList(pemBlock.Bytes)
			if err != nil {
				return fmt.Errorf("failed to parse certificate for issuer (%v): %w", issuer, err)
			}

			deltaRet.ParsedCache["crl"] = cert
		}

		h.DeltaCRLs[issuer] = deltaRet.ParsedCache["crl"].(*x509.RevocationList)
	}

	// Check if the issuer is fetched yet.
	configRet, err := e.FetchIfNotFetched(logical.ReadOperation, "/{{mount}}/config/crl")
	if err != nil {
		return err
	}

	h.CRLConfig = configRet

	return nil
}

func (h *CRLValidityPeriod) Evaluate(e *Executor) (results []*Result, err error) {
	if !h.Enabled {
		return nil, nil
	} else if h.UnsupportedVersion {
		ret := Result{
			Status:   ResultInvalidVersion,
			Endpoint: "/{{mount}}/issuers",
			Message:  "This health check requires Vault 1.11+ but an earlier version of Vault Server was contacted, preventing this health check from running.",
		}
		return []*Result{&ret}, nil
	}

	if h.CRLConfig.IsSecretPermissionsError() {
		ret := Result{
			Status:   ResultInsufficientPermissions,
			Endpoint: "/{{mount}}/config/crl",
			Message:  "This prevents the health check from seeing if the CRL is disabled and dropping the severity of this check accordingly.",
		}

		if e.Client.Token() == "" {
			ret.Message = "No token available so unable read authenticated CRL configuration for this mount. " + ret.Message
		} else {
			ret.Message = "This token lacks so permission to read the CRL configuration for this mount. " + ret.Message
		}

		results = append(results, &ret)
	}

	if h.NoDeltas {
		ret := Result{
			Status:   ResultInvalidVersion,
			Endpoint: "/{{mount}}/issuer/*/crl/delta",
			Message:  "This health check validates Delta CRLs on Vault 1.12+, but an earlier version of Vault was used. No results about delta CRL validity will be returned.",
		}
		results = append(results, &ret)
	}

	for name, crl := range h.CRLs {
		var ret Result
		ret.Status = ResultOK
		ret.Endpoint = "/{{mount}}/issuer/" + name + "/crl"
		ret.Message = fmt.Sprintf("CRL's validity (%v to %v) is OK.", crl.ThisUpdate.Format("2006-01-02"), crl.NextUpdate.Format("2006-01-02"))

		results = append(results, &ret)
	}

	return
}
