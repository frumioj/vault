package pki

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/certutil"
	"github.com/hashicorp/vault/sdk/helper/errutil"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	crlNumberParam  = "crl_number"
	nextUpdateParam = "next_update"
	crlsParam       = "crls"
	formatParam     = "format"
)

func pathResignCrls(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "issuer/" + framework.GenericNameRegex(issuerRefParam) + "/resign-crls",
		Fields: map[string]*framework.FieldSchema{
			issuerRefParam: {
				Type:        framework.TypeString,
				Description: ``,
			},
			crlNumberParam: {
				Type:        framework.TypeInt,
				Description: ``,
			},
			nextUpdateParam: {
				Type:        framework.TypeString,
				Description: ``,
			},
			crlsParam: {
				Type:        framework.TypeStringSlice,
				Description: ``,
			},
			formatParam: {
				Type:        framework.TypeString,
				Description: ``,
				Default:     "pem",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathUpdateResignCrls,
			},
		},

		HelpSynopsis:    "",
		HelpDescription: "",
	}
}

func (b *backend) pathUpdateResignCrls(ctx context.Context, request *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	issuerRef := getIssuerRef(data)
	crlNumber := data.Get(crlNumberParam).(int)
	nextUpdateStr := data.Get(nextUpdateParam).(string)
	rawCrls := data.Get(crlsParam).([]string)

	format, err := getCrlFormat(data.Get(formatParam).(string))
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	signingBundle, err := getIssuer(ctx, b, request, issuerRef)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	nextUpdateOffset, err := time.ParseDuration(nextUpdateStr)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("invalid value for %s: %v", nextUpdateParam, err)), nil
	}

	revokedCerts, err := getAllRevokedCerts(rawCrls)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	now := time.Now()
	template := &x509.RevocationList{
		SignatureAlgorithm:  signingBundle.RevocationSigAlg,
		RevokedCertificates: revokedCerts,
		Number:              big.NewInt(int64(crlNumber)),
		ThisUpdate:          now,
		NextUpdate:          now.Add(nextUpdateOffset),
	}

	crlBytes, err := x509.CreateRevocationList(rand.Reader, template, signingBundle.Certificate, signingBundle.PrivateKey)
	if err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("error creating new CRL: %s", err)}
	}

	contentType, body := encodeResponse(format, crlBytes)

	return &logical.Response{
		Data: map[string]interface{}{
			logical.HTTPStatusCode:  http.StatusOK,
			logical.HTTPContentType: contentType,
			logical.HTTPRawBody:     body,
		},
	}, nil
}

func encodeResponse(format string, crlBytes []byte) (string, string) {
	var contentType string
	var body string
	switch format {
	case "pem":
		contentType = "application/x-pem-file"
		block := pem.Block{
			Type:  "X509 CRL",
			Bytes: crlBytes,
		}
		// This is convoluted on purpose to ensure that we don't have trailing
		// newlines via various paths
		body = strings.TrimSpace(string(pem.EncodeToMemory(&block)))
	case "der":
		contentType = "application/pkix-crl"
		body = string(crlBytes)
	}
	return contentType, body
}

func getCrlFormat(requestedValue string) (string, error) {
	format := strings.ToLower(requestedValue)
	switch format {
	case "pem", "der":
		return format, nil
	default:
		return "", fmt.Errorf("unknown format value of %s", requestedValue)
	}
}

func getAllRevokedCerts(rawCrls []string) ([]pkix.RevokedCertificate, error) {
	var crls []*x509.RevocationList
	for i, rawCrl := range rawCrls {
		crl, err := decodePemCrl(rawCrl)
		if err != nil {
			return nil, fmt.Errorf("failed decoding crl %d: %v", i, err)
		}
		crls = append(crls, crl)
	}

	var revokedCerts []pkix.RevokedCertificate
	for _, crl := range crls {
		revokedCerts = append(revokedCerts, crl.RevokedCertificates...)
	}
	return revokedCerts, nil
}

func getIssuer(ctx context.Context, b *backend, request *logical.Request, issuerRef string) (*certutil.CAInfoBundle, error) {
	sc := b.makeStorageContext(ctx, request.Storage)
	issuerId, err := sc.resolveIssuerReference(issuerRef)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve issuer %s: %v", issuerRefParam, err)
	}

	signingBundle, err := sc.fetchCAInfoByIssuerId(issuerId, CRLSigningUsage)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch issuer with id %s: %v", issuerId, err)
	}

	return signingBundle, nil
}

func decodePemCrl(crl string) (*x509.RevocationList, error) {
	block, rest := pem.Decode([]byte(crl))
	if len(rest) != 0 {
		return nil, fmt.Errorf("invalid crl; should be one PEM block only")
	}

	return x509.ParseRevocationList(block.Bytes)
}
