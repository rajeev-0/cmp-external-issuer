package signer

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSign(t *testing.T) {
	// Create a sample signer
	signer := &exampleSigner{}

	csr := `-----BEGIN CERTIFICATE REQUEST-----
MIIBBDCBrAIBADBKMRgwFgYDVQQDDA90ZXN0LWt1YmVybmV0ZXMxDzANBgNVBAsM
BklEZXZJRDEQMA4GA1UECgwHU2llbWVuczELMAkGA1UEBhMCREUwWTATBgcqhkjO
PQIBBggqhkjOPQMBBwNCAAQxWqUKqBRCMBrOyQmbzRjkK8bFIf55LsjloQ1cMEHy
o+nHUEQ0TwujaBcPRDDvL2L5ICcecRufJZoS57xjLXuroAAwCgYIKoZIzj0EAwID
RwAwRAIgcsE1ctNfOtQsbRMhl4LdL7FHD/SnFWHXjHIEC8fzH70CIBCEbD+K4HOi
viR8j2UiRd8wqYg1mNZpnW7U4MKQGauZ
-----END CERTIFICATE REQUEST-----`
	// Define the input CSR bytes
	csrBytes := []byte(csr)

	// Call the Sign function
	signature, err := signer.Sign(csrBytes)

	// Assert that no error occurred
	if err != nil {
		t.Errorf("Error occurred during signing: %v", err)
	}

	// Assert that the signature is not empty
	assert.NotEmpty(t, signature)
}