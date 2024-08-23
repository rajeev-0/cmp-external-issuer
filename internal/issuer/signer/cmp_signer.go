package signer

import (
	"bytes"
	"crypto"
	"crypto/rand"
	x509 "crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"reflect"
	"time"

	sampleissuerapi "github.com/cert-manager/sample-external-issuer/api/v1alpha1"
)

type HealthChecker interface {
	Check() error
}

type HealthCheckerBuilder func(*sampleissuerapi.IssuerSpec, map[string][]byte) (HealthChecker, error)

type Signer interface {
	Sign([]byte) ([]byte, error)
}

type SignerBuilder func(*sampleissuerapi.IssuerSpec, map[string][]byte) (Signer, error)

func ExampleHealthCheckerFromIssuerAndSecretData(*sampleissuerapi.IssuerSpec, map[string][]byte) (HealthChecker, error) {
	return &exampleSigner{}, nil
}

func ExampleSignerFromIssuerAndSecretData(*sampleissuerapi.IssuerSpec, map[string][]byte) (Signer, error) {
	return &exampleSigner{}, nil
}

type exampleSigner struct {
}

func (o *exampleSigner) Check() error {
	return nil
}

func (o *exampleSigner) Sign(csrBytes []byte) ([]byte, error) {

	senderCommonName := "CloudCA-Integration-Test-User"
	senderDN := Name{
		[]pkix.AttributeTypeAndValue{
			{Type: oidCommonName, Value: senderCommonName}}}

	recipientCommonName := "CloudPKI-Integration-Test"
	recipientDN := Name{
		[]pkix.AttributeTypeAndValue{
			{Type: oidCommonName, Value: recipientCommonName}}}

	//sharedSecret := "SiemensIT"
	sharedSecret := "secretcmp"

	//url := "https://broker.sdo-dev.siemens.cloud/.well-known/cmp"
	url := "http://129.103.177.164:6080/ejbca/publicweb/cmp/cmp_imprint_RA"

	randomTransactionID, _ := createRandom(16)

	randomSenderNonce, _ := createRandom(16)
	randomRecipNonce, _ := createRandom(16)

	/*
	   	csr := `-----BEGIN CERTIFICATE REQUEST-----
	   MIIEwDCCAqgCAQAwGzEZMBcGA1UEAxMQdGVzdC5leGFtcGxlLmNvbTCCAiIwDQYJ
	   KoZIhvcNAQEBBQADggIPADCCAgoCggIBAJYtP4iLdUBt96pl3Exrz/UXzSuTsZ+i
	   f7cnoFz+DyzS3+6pPLSS7o37g8xxZlqJecY6CfDeLY40maFIsHM4CgkVldwdy4F7
	   SByFwVZseozGoWGOSSD2ceSMA6qgKmgSRUqwumLJdOJqc5bDQYQqPYabp66hrm9q
	   VNGlC33XPJ5btITCTwWp+3LNcUYdAPDsMSY/MF8ejExITKjj8M/Xt82vSxY4VNl8
	   kkSvwmOSSdfzpyl1MN9+zVslUyGJywQyV4vcLqJrM9C32nnh1SY4oE000GTGSbIa
	   w5kolzrsSBVmLxuNhrgrg4IHZMaYn1OtrI3yVUXuAU0CENHfpUo20CBjTt43ReBo
	   2HXPoWbxULUOqIDQQELl3ZMOxjt7owXfm5go7EsqMKbPAKtHGuFZkVe/C6JYheWQ
	   nl0mGC2yfhEix3zviReTmocLLWAeTz3bVO3+jD3aKliv/RA1zyYIwWycAZuVJ17o
	   e2ceBnHM0/ccO/3giERqHIn+u8hUduCRIo+S1bEB6/Mf91QYFX63uPkYzs4TW/1I
	   3pklIOiYCbedVORs+U7GMcgPMOa6+oZHYsd2Q/kFly7K0RfhY/g/YTGkLW4LhXSU
	   /lplOSZEasTrz5az8cdJK4JL8OAfCe6qN6gKMNNhTJC3AYVa0ATbazGvQdkEHCNn
	   mFr4VRwVfV2zAgMBAAGgYDBeBgkqhkiG9w0BCQ4xUTBPMAwGA1UdEwEB/wQCMAAw
	   HQYDVR0OBBYEFIa6xq2GOW+R3JVCWZMwTadF7m+2MAsGA1UdDwQEAwIDuDATBgNV
	   HSUEDDAKBggrBgEFBQcDAjANBgkqhkiG9w0BAQ0FAAOCAgEAkiXuuU3/dXh3fYX2
	   agt3JoJ8+GmPSVLvLbwiCkxNnJkI28gpn0BROO+QGUSHRSVaoUM1/GYb1XpXQvDd
	   LIC5ZC/jlXpC5/PcnvCOQu3YJmEQeDub6YrFcFLMkf1dhOBfEywrEZwfyQ/2tNUZ
	   FU9yiW0gF015651y8Xl0WMCCi8nsZ19o8MI2zzzafvpyk0M66IYq1GpRM4MzHcnf
	   YzA4RygZwlrf1fiMjPrzY0oh3U53M1ejGBoAAHSqNJ0rf02FU0U+5M8SaoById8v
	   ITgegC1Gsga/ox41Leiiinqudije+BX66wze/ZnjKFMfjlg2vBQChzyrTOZ07U2w
	   T7v8Ey0Go0meB7sjyaKVrJiinI95Woyk/JrvUbTXW6lSVBiTkj+PKQGaGT3otIDo
	   8HWI35EWs0FoKndUh3MznvsnRycf+7cPoS3prVThmA+bxS1z+pMFwYRFhl63OCQP
	   kCDAJsS9LESD2wDIrv7Hmxu9SAVwqmil8KMNlwGbBj+MzE9OUUTmL7BQYujVVV8i
	   MdBk6ysluKbfbolzkPKZxdZHs9YsC3szT8a7U1OY/tABBrF3D6cbEJFZgscuZFgW
	   LSnod9g7TZsgTN3TY9V6xj6tERl+0/kMTcnQV55UOWAPCQqk0SrwdB9i2ebZCVgQ
	   1qrQsPB5Gv8K5COmC9b7VY4czB4=
	   -----END CERTIFICATE REQUEST-----
	   `
	   	certificateRequest, _ := pem.Decode([]byte(csr))
	   	if certificateRequest == nil {
	   		log.Fatal("failed to decode PEM block containing the CSR")
	   	}
	   	parsedCSR, _ := x509.ParseCertificateRequest(certificateRequest.Bytes)
	*/
	parsedCSR, err := parseCSR(csrBytes)
	if err != nil {
		return nil, err
	}
	csrPublicKey := parsedCSR.PublicKey

	randomSalt, _ := createRandom(16)

	p10RequestMessage := PKIMessage{
		Header: PKIHeader{
			PVNO:        CMP2000,
			Sender:      ChoiceConvert(senderDN, directoryName),
			Recipient:   ChoiceConvert(recipientDN, directoryName),
			MessageTime: time.Now(),
			ProtectionAlg: AlgorithmIdentifier{
				Algorithm: oidPBM,
				Parameters: PBMParameter{
					Salt: randomSalt,
					OWF: AlgorithmIdentifier{
						Algorithm:  oidSHA512,
						Parameters: []byte{},
					},
					IterationCount: 10000,
					MAC: AlgorithmIdentifier{
						Algorithm:  oidHMACWithSHA512,
						Parameters: []byte{},
					},
				},
			},
			SenderKID:     KeyIdentifier(senderDN.String()),
			RecipientKID:  KeyIdentifier(recipientDN.String()),
			TransactionID: randomTransactionID,
			SenderNonce:   randomSenderNonce,
			RecipNonce:    randomRecipNonce,
		},
		Body: asn1.RawValue{Bytes: parsedCSR.Raw, IsCompound: true, Class: asn1.ClassContextSpecific, Tag: PKCS10CertificationRequest},
	}

	responseBody, cmpsenderr := sendCMPMessage(p10RequestMessage, sharedSecret, url)

	if cmpsenderr != nil {
		return nil, cmpsenderr
	}
	var responseMessage PKIMessage
	asn1.Unmarshal(responseBody, &responseMessage)

	if !bytes.Equal(responseMessage.Header.TransactionID, randomTransactionID) {
		return nil, errors.New("TransactionID is not equale")
	}

	if !bytes.Equal(randomSenderNonce, responseMessage.Header.RecipNonce) {
		return nil, errors.New("Nonce is not equale")
	}

	if responseMessage.Body.Tag == ErrorMessage {
		var pkierrmsg ErrorMsgContent
		asn1.Unmarshal(responseMessage.Body.Bytes, &pkierrmsg)
		errstring := fmt.Sprintf("CMP Error message(23): Status : %v, %s", pkierrmsg.PKIStatusInfo.Status, pkierrmsg.PKIStatusInfo.StatusString)
		return nil, errors.New(errstring)
	}

	if responseMessage.Body.Tag != CertificationResponse {
		errstring := fmt.Sprintf("IP message of type %v", responseMessage.Body.Tag)
		return nil, errors.New(errstring)
	}

	var certRepMessage CertRepMessage
	asn1.Unmarshal(responseMessage.Body.Bytes, &certRepMessage)

	if len(certRepMessage.Response) != 1 {
		errstring := fmt.Sprintf("Response contained %v certificates", len(certRepMessage.Response))
		return nil, errors.New(errstring)
	}

	if certRepMessage.Response[0].CertifiedKeyPair.CertOrEncCert.Tag != Certificate {
		errstring := fmt.Sprintf("Response certificate of type %v", certRepMessage.Response[0].CertifiedKeyPair.CertOrEncCert.Tag)
		return nil, errors.New(errstring)
	}

	certificate, _ := x509.ParseCertificate(certRepMessage.Response[0].CertifiedKeyPair.CertOrEncCert.Bytes)

	fmt.Printf("Certificate issued to %v\n", certificate.Subject)
	fmt.Printf("Certificate issued by %v\n", certificate.Issuer)
	fmt.Printf("Certificate valid from %v\n", certificate.NotBefore)
	fmt.Printf("Certificate valid until %v\n", certificate.NotAfter)

	block := &pem.Block{
		Type:    "CERTIFICATE",
		Headers: nil,
		Bytes:   certificate.Raw,
	}
	pem.Encode(os.Stdout, block)

	if !reflect.DeepEqual(csrPublicKey, certificate.PublicKey) {
		return nil, errors.New("Certificate doesn't match to key provided in CSR")
	}

	/*
	   certHash    OCTET STRING,
	   -- the hash of the certificate, using the same hash algorithm
	   -- as is used to create and verify the certificate signature
	*/
	signAlgorithm := certificate.SignatureAlgorithm

	var hashType crypto.Hash

	for _, details := range signatureAlgorithmDetails {
		if details.algo == signAlgorithm {
			hashType = details.hash
		}
	}

	hashFunc := hashType.New()

	hashFunc.Reset()
	hashFunc.Write(certificate.Raw)
	certHash := hashFunc.Sum(nil)

	randomSenderNonce, _ = createRandom(16)
	randomSalt, _ = createRandom(16)

	certConfMessage := PKIMessage{
		Header: PKIHeader{
			PVNO:        CMP2000,
			Sender:      ChoiceConvert(senderDN, directoryName),
			Recipient:   ChoiceConvert(recipientDN, directoryName),
			MessageTime: time.Now(),
			ProtectionAlg: AlgorithmIdentifier{
				Algorithm: oidPBM,
				Parameters: PBMParameter{
					Salt: randomSalt,
					OWF: AlgorithmIdentifier{
						Algorithm:  oidSHA512,
						Parameters: []byte{},
					},
					IterationCount: 10000,
					MAC: AlgorithmIdentifier{
						Algorithm:  oidHMACWithSHA512,
						Parameters: []byte{},
					},
				},
			},
			SenderKID:     KeyIdentifier(senderDN.String()),
			RecipientKID:  KeyIdentifier(recipientDN.String()),
			TransactionID: randomTransactionID,
			SenderNonce:   randomSenderNonce,
			RecipNonce:    responseMessage.Header.SenderNonce,
		},
		Body: ChoiceConvert(CertConfirmContent{
			CertStatus{
				CertHash:  certHash,
				CertReqID: 0,
			},
		}, CertificateConfirm),
	}

	certConfResponseBody, cmperr := sendCMPMessage(certConfMessage, sharedSecret, url)
	if cmperr != nil {
		return nil, cmperr
	}

	var pkiConfMessage PKIMessage
	asn1.Unmarshal(certConfResponseBody, &pkiConfMessage)

	if !bytes.Equal(pkiConfMessage.Header.TransactionID, randomTransactionID) {
		return nil, errors.New("pkiconf TransactionID is not equale")
	}

	if !bytes.Equal(randomSenderNonce, pkiConfMessage.Header.RecipNonce) {
		return nil, errors.New("pkiconf Nonce is not equale")
	}

	if pkiConfMessage.Body.Tag != Confirmation {
		errstring := fmt.Sprintf("Response message of type %v", responseMessage.Body.Tag)
		return nil, errors.New(errstring)
	}

	fmt.Println("All done!")
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certificate.Raw,
	}), nil
}

func sendCMPMessage(requestMessage PKIMessage, sharedSecret string, url string) (body []byte, err error) {
	requestMessage.Protect(sharedSecret)

	pkiMessageAsDER, err1 := asn1.Marshal(requestMessage)
	if err1 != nil {
		fmt.Errorf("Error marshaling structure 1: %v", err1)
		return nil, err1
	}

	client := &http.Client{}

	resp, err := client.Post(url, "application/pkixcmp", bytes.NewReader(pkiMessageAsDER))
	if err != nil {
		fmt.Printf("Error: %v", err)
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		fmt.Printf("Status code %v doesn't equal 200", resp.Status)
		return nil, errors.New("Status code doesn't equal 200")
	}

	body, err = io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %v", err)
		return nil, err
	}

	return
}

func createRandom(n int) (randomValue []byte, err error) {
	randomValue = make([]byte, n)
	nRead, err := rand.Read(randomValue)

	if err != nil {
		fmt.Printf("Read err %v", err)
		return nil, err
	}
	if nRead != n {
		fmt.Printf("Read returned unexpected n; %d != %d", nRead, n)
		return nil, errors.New("Read returned unexpected n")
	}
	return
}

func parseCSR(pemBytes []byte) (*x509.CertificateRequest, error) {
	// extract PEM from request object
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("PEM block type must be CERTIFICATE REQUEST")
	}
	return x509.ParseCertificateRequest(block.Bytes)
}
