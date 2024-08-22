package signer

import (
	"crypto"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"hash"
	"time"
)

/*
	CertRepMessage ::= SEQUENCE {
	    caPubs          [1] SEQUENCE SIZE (1..MAX) OF Certificate
	                        OPTIONAL,
	    response            SEQUENCE OF CertResponse
	}
*/
type CertRepMessage struct {
	CAPubs   []asn1.RawValue `asn1:"optional,tag:1,omitempty"`
	Response []CertResponse
}

/*
	CertResponse ::= SEQUENCE {
	    certReqId           INTEGER,
	    status              PKIStatusInfo,
	    certifiedKeyPair    CertifiedKeyPair    OPTIONAL,
	    rspInfo             OCTET STRING        OPTIONAL
	    -- analogous to the id-regInfo-utf8Pairs string defined
	    -- for regInfo in CertReqMsg [CRMF]
	}
*/
type CertResponse struct {
	CertReqID        int
	Status           asn1.RawValue
	CertifiedKeyPair CertifiedKeyPair `asn1:"optional,omitempty"`
	RSPInfo          []byte           `asn1:"optional,omitempty"`
}

/*
	CertifiedKeyPair ::= SEQUENCE {
	    certOrEncCert       CertOrEncCert,
	    privateKey      [0] EncryptedValue      OPTIONAL,
	    -- see [CRMF] for comment on encoding
	    publicationInfo [1] PKIPublicationInfo  OPTIONAL
	}
*/
type CertifiedKeyPair struct {
	CertOrEncCert   asn1.RawValue
	PrivateKey      asn1.RawValue `asn1:"optional,omitempty"`
	PublicationInfo asn1.RawValue `asn1:"optional,omitempty"`
}

/*
	CertOrEncCert ::= CHOICE {
	    certificate     [0] Certificate,
	    encryptedCert   [1] EncryptedValue
	}
*/
const (
	Certificate = iota
	EncryptedValue
)

var (
	oidCountry            = asn1.ObjectIdentifier{2, 5, 4, 6}
	oidOrganization       = asn1.ObjectIdentifier{2, 5, 4, 10}
	oidOrganizationalUnit = asn1.ObjectIdentifier{2, 5, 4, 11}
	oidCommonName         = asn1.ObjectIdentifier{2, 5, 4, 3}
	oidSerialNumber       = asn1.ObjectIdentifier{2, 5, 4, 5}
	oidLocality           = asn1.ObjectIdentifier{2, 5, 4, 7}
	oidProvince           = asn1.ObjectIdentifier{2, 5, 4, 8}
	oidStreetAddress      = asn1.ObjectIdentifier{2, 5, 4, 9}
	oidPostalCode         = asn1.ObjectIdentifier{2, 5, 4, 17}
)

var (
	oidHMACWithSHA1   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 8, 1, 2}
	oidHMACWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidHMACWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 10}
	oidHMACWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 11}

	oidSHA1 = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}

	oidPBM = asn1.ObjectIdentifier{1, 2, 840, 113533, 7, 66, 13}
)

// https://cs.opensource.google/go/go/+/refs/tags/go1.21.6:src/crypto/x509/x509.go;l=327
var (
	oidSignatureMD2WithRSA      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 2}
	oidSignatureMD5WithRSA      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 4}
	oidSignatureSHA1WithRSA     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	oidSignatureSHA256WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSignatureSHA384WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSignatureSHA512WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidSignatureRSAPSS          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	oidSignatureDSAWithSHA1     = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 3}
	oidSignatureDSAWithSHA256   = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 2}
	oidSignatureECDSAWithSHA1   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}
	oidSignatureECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidSignatureECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidSignatureECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
	oidSignatureEd25519         = asn1.ObjectIdentifier{1, 3, 101, 112}

	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}

	oidMGF1 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}

	// oidISOSignatureSHA1WithRSA means the same as oidSignatureSHA1WithRSA
	// but it's specified by ISO. Microsoft's makecert.exe has been known
	// to produce certificates with this OID.
	oidISOSignatureSHA1WithRSA = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 29}
)

// https://cs.opensource.google/go/go/+/refs/tags/go1.21.6:src/crypto/x509/x509.go;l=355
var signatureAlgorithmDetails = []struct {
	algo       x509.SignatureAlgorithm
	name       string
	oid        asn1.ObjectIdentifier
	pubKeyAlgo x509.PublicKeyAlgorithm
	hash       crypto.Hash
}{
	{x509.MD2WithRSA, "MD2-RSA", oidSignatureMD2WithRSA, x509.RSA, crypto.Hash(0) /* no value for MD2 */},
	{x509.MD5WithRSA, "MD5-RSA", oidSignatureMD5WithRSA, x509.RSA, crypto.MD5},
	{x509.SHA1WithRSA, "SHA1-RSA", oidSignatureSHA1WithRSA, x509.RSA, crypto.SHA1},
	{x509.SHA1WithRSA, "SHA1-RSA", oidISOSignatureSHA1WithRSA, x509.RSA, crypto.SHA1},
	{x509.SHA256WithRSA, "SHA256-RSA", oidSignatureSHA256WithRSA, x509.RSA, crypto.SHA256},
	{x509.SHA384WithRSA, "SHA384-RSA", oidSignatureSHA384WithRSA, x509.RSA, crypto.SHA384},
	{x509.SHA512WithRSA, "SHA512-RSA", oidSignatureSHA512WithRSA, x509.RSA, crypto.SHA512},
	{x509.SHA256WithRSAPSS, "SHA256-RSAPSS", oidSignatureRSAPSS, x509.RSA, crypto.SHA256},
	{x509.SHA384WithRSAPSS, "SHA384-RSAPSS", oidSignatureRSAPSS, x509.RSA, crypto.SHA384},
	{x509.SHA512WithRSAPSS, "SHA512-RSAPSS", oidSignatureRSAPSS, x509.RSA, crypto.SHA512},
	{x509.DSAWithSHA1, "DSA-SHA1", oidSignatureDSAWithSHA1, x509.DSA, crypto.SHA1},
	{x509.DSAWithSHA256, "DSA-SHA256", oidSignatureDSAWithSHA256, x509.DSA, crypto.SHA256},
	{x509.ECDSAWithSHA1, "ECDSA-SHA1", oidSignatureECDSAWithSHA1, x509.ECDSA, crypto.SHA1},
	{x509.ECDSAWithSHA256, "ECDSA-SHA256", oidSignatureECDSAWithSHA256, x509.ECDSA, crypto.SHA256},
	{x509.ECDSAWithSHA384, "ECDSA-SHA384", oidSignatureECDSAWithSHA384, x509.ECDSA, crypto.SHA384},
	{x509.ECDSAWithSHA512, "ECDSA-SHA512", oidSignatureECDSAWithSHA512, x509.ECDSA, crypto.SHA512},
	{x509.PureEd25519, "Ed25519", oidSignatureEd25519, x509.Ed25519, crypto.Hash(0) /* no pre-hashing */},
}

/*
In the above protectionAlg, the salt value is appended to the shared
secret input.  The OWF is then applied iterationCount times, where
the salted secret is the input to the first iteration and, for each
successive iteration, the input is set to be the output of the
previous iteration.  The output of the final iteration (called
"BASEKEY" for ease of reference, with a size of "H") is what is used
to form the symmetric key.
*/
func deriveBaseKey(sharedSecret string, salt []byte, owf hash.Hash, iterations int) (baseKey []byte) {
	// Initial hash is the password + salt
	sharedSecretByteArray := []byte(sharedSecret)
	calculatingBaseKey := append(sharedSecretByteArray, salt...)

	for i := 0; i < iterations; i++ {
		owf.Reset()
		owf.Write(calculatingBaseKey)
		calculatingBaseKey = owf.Sum(nil)
	}

	baseKey = calculatingBaseKey

	return
}

func (pkiMessage *PKIMessage) Protect(sharedSecret string) (err error) {
	pkiProtection := struct {
		Header PKIHeader
		Body   asn1.RawValue
	}{Header: pkiMessage.Header,
		Body: pkiMessage.Body}

	messsageByteString, err1 := asn1.Marshal(pkiProtection)
	if err1 != nil {
		err = err1
		return
	}

	protAlgorithm := pkiMessage.Header.ProtectionAlg

	if !protAlgorithm.Algorithm.Equal(oidPBM) {
		err = errors.New("only PBM supported as protection Algorithm")
		return
	}

	pbmParameter := protAlgorithm.Parameters.(PBMParameter)

	var oneWayFunction hash.Hash

	switch {
	case oidSHA1.Equal(pbmParameter.OWF.Algorithm):
		oneWayFunction = sha1.New()
	case oidSHA256.Equal(pbmParameter.OWF.Algorithm):
		oneWayFunction = sha256.New()
	case oidSHA384.Equal(pbmParameter.OWF.Algorithm):
		oneWayFunction = sha512.New384()
	case oidSHA512.Equal(pbmParameter.OWF.Algorithm):
		oneWayFunction = sha512.New()
	default:
		err = errors.New("only SHA1, SHA256, SHA384 and SHA512 supported as OWF")
		return
	}

	baseKey := deriveBaseKey(sharedSecret, pbmParameter.Salt, oneWayFunction, pbmParameter.IterationCount)

	var hmacFunction hash.Hash

	switch {
	case oidHMACWithSHA1.Equal(pbmParameter.MAC.Algorithm):
		hmacFunction = hmac.New(sha1.New, baseKey)
	case oidHMACWithSHA256.Equal(pbmParameter.MAC.Algorithm):
		hmacFunction = hmac.New(sha256.New, baseKey)
	case oidHMACWithSHA384.Equal(pbmParameter.MAC.Algorithm):
		hmacFunction = hmac.New(sha512.New384, baseKey)
	case oidHMACWithSHA512.Equal(pbmParameter.MAC.Algorithm):
		hmacFunction = hmac.New(sha512.New, baseKey)
	default:
		err = errors.New("only SHA1, SHA256, SHA384 and SHA512 supported as HashFunction")
		return
	}

	hmacFunction.Write(messsageByteString)
	protectionByteArray := hmacFunction.Sum(nil)

	pkiMessage.Protection = PKIProtection{Bytes: asn1.BitString{Bytes: protectionByteArray, BitLength: len(protectionByteArray) * 8}}

	return
}

/*
   PKIBody ::= CHOICE {       -- message-specific body elements
       ir       [0]  CertReqMessages,        --Initialization Request
       ip       [1]  CertRepMessage,         --Initialization Response
       cr       [2]  CertReqMessages,        --Certification Request
       cp       [3]  CertRepMessage,         --Certification Response
       p10cr    [4]  CertificationRequest,   --imported from [PKCS10]
       popdecc  [5]  POPODecKeyChallContent, --pop Challenge
       popdecr  [6]  POPODecKeyRespContent,  --pop Response
       kur      [7]  CertReqMessages,        --Key Update Request
       kup      [8]  CertRepMessage,         --Key Update Response
       krr      [9]  CertReqMessages,        --Key Recovery Request
       krp      [10] KeyRecRepContent,       --Key Recovery Response
       rr       [11] RevReqContent,          --Revocation Request
       rp       [12] RevRepContent,          --Revocation Response
       ccr      [13] CertReqMessages,        --Cross-Cert. Request
       ccp      [14] CertRepMessage,         --Cross-Cert. Response
       ckuann   [15] CAKeyUpdAnnContent,     --CA Key Update Ann.
       cann     [16] CertAnnContent,         --Certificate Ann.
       rann     [17] RevAnnContent,          --Revocation Ann.
       crlann   [18] CRLAnnContent,          --CRL Announcement
       pkiconf  [19] PKIConfirmContent,      --Confirmation
       nested   [20] NestedMessageContent,   --Nested Message
       genm     [21] GenMsgContent,          --General Message
       genp     [22] GenRepContent,          --General Response
       error    [23] ErrorMsgContent,        --Error Message
       certConf [24] CertConfirmContent,     --Certificate confirm
       pollReq  [25] PollReqContent,         --Polling request
       pollRep  [26] PollRepContent          --Polling response
   }
*/

const (
	InitializationRequest = iota
	InitializationResponse
	CertificationRequest
	CertificationResponse
	PKCS10CertificationRequest
	POPChallenge
	POPResponse
	KeyUpdateRequest
	KeyUpdateResponse
	KeyRecoveryRequest
	KeyRecoveryResponse
	RevocationRequest
	RevocationResponse
	CrossCertRequest
	CrossCertResponse
	CAKeyUpdateAnnouncement
	CertificateAnnouncement
	RevocationAnnouncement
	CRLAnnouncement
	Confirmation
	NestedMessage
	GeneralMessage
	GeneralResponse
	ErrorMessage
	CertificateConfirm
	PollingRequest
	PollingResponse
)

/*
PKIFreeText ::= SEQUENCE SIZE (1..MAX) OF UTF8String

	-- text encoded as UTF-8 String [RFC3629] (note: each
	-- UTF8String MAY include an [RFC3066] language tag
	-- to indicate the language of the contained text
	-- see [RFC2482] for details)
*/
type PKIFreeText []string

type Name pkix.RDNSequence

func (name Name) String() (result string) {
	return pkix.RDNSequence(name).String()
}

type IA5String string

func ChoiceConvert(source any, contextSpecificTag int) (result asn1.RawValue) {
	result = asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        contextSpecificTag,
		IsCompound: true,
		Bytes: func() []byte {
			b, _ := asn1.Marshal(source)
			return b
		}(),
	}
	return
}

type GeneralName asn1.RawValue

/*
	GeneralName ::= CHOICE {
		otherName                       [0]     AnotherName,
		rfc822Name                      [1]     IA5String,
		dNSName                         [2]     IA5String,
		x400Address                     [3]     ORAddress,
		directoryName                   [4]     Name,
		ediPartyName                    [5]     EDIPartyName,
		uniformResourceIdentifier       [6]     IA5String,
		iPAddress                       [7]     OCTET STRING,
		registeredID                    [8]     OBJECT IDENTIFIER }
*/
const (
	otherName = iota
	rfc822Name
	dNSName
	x400Address
	directoryName
	ediPartyName
	uniformResourceIdentifier
	iPAddress
	registeredID
)

type KeyIdentifier []byte

/*
	PBMParameter ::= SEQUENCE {
	    salt                OCTET STRING,
	    -- note:  implementations MAY wish to limit acceptable sizes
	    -- of this string to values appropriate for their environment
	    -- in order to reduce the risk of denial-of-service attacks
	    owf                 AlgorithmIdentifier,
	    -- AlgId for a One-Way Function (SHA-1 recommended)
	    iterationCount      INTEGER,
	    -- number of times the OWF is applied
	    -- note:  implementations MAY wish to limit acceptable sizes
	    -- of this integer to values appropriate for their environment
	    -- in order to reduce the risk of denial-of-service attacks
	    mac                 AlgorithmIdentifier
	    -- the MAC AlgId (e.g., DES-MAC, Triple-DES-MAC [PKCS11],
	}   -- or HMAC [RFC2104, RFC2202])
*/
type PBMParameter struct {
	Salt           []byte
	OWF            AlgorithmIdentifier
	IterationCount int
	MAC            AlgorithmIdentifier
}

/*
AlgorithmIdentifier  ::=  SEQUENCE  {
	algorithm               OBJECT IDENTIFIER,
	parameters              ANY DEFINED BY algorithm OPTIONAL  }
							   -- contains a value of the type
							   -- registered for use with the
							   -- algorithm object identifier value
*/

type AlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters any `asn1:"optional,omitempty"`
}

const (
	CMP1999 = iota + 1
	CMP2000
	CMP2021
)

/*
PKIHeader ::= SEQUENCE {
         pvno                INTEGER     { cmp1999(1), cmp2000(2) },
         sender              GeneralName,
         -- identifies the sender
         recipient           GeneralName,
         -- identifies the intended recipient
         messageTime     [0] GeneralizedTime         OPTIONAL,
         -- time of production of this message (used when sender
         -- believes that the transport will be "suitable"; i.e.,
         -- that the time will still be meaningful upon receipt)
         protectionAlg   [1] AlgorithmIdentifier     OPTIONAL,
         -- algorithm used for calculation of protection bits
         senderKID       [2] KeyIdentifier           OPTIONAL,
         recipKID        [3] KeyIdentifier           OPTIONAL,
         -- to identify specific keys used for protection
         transactionID   [4] OCTET STRING            OPTIONAL,
         -- identifies the transaction; i.e., this will be the same in
         -- corresponding request, response, certConf, and PKIConf
         -- messages
         senderNonce     [5] OCTET STRING            OPTIONAL,
         recipNonce      [6] OCTET STRING            OPTIONAL,
         -- nonces used to provide replay protection, senderNonce
         -- is inserted by the creator of this message; recipNonce
         -- is a nonce previously inserted in a related message by
         -- the intended recipient of this message
         freeText        [7] PKIFreeText             OPTIONAL,
         -- this may be used to indicate context-specific instructions
         -- (this field is intended for human consumption)
         generalInfo     [8] SEQUENCE SIZE (1..MAX) OF
                                InfoTypeAndValue     OPTIONAL
         -- this may be used to convey context-specific information
         -- (this field not primarily intended for human consumption)
     }
*/

type PKIHeader struct {
	PVNO          int
	Sender        asn1.RawValue
	Recipient     asn1.RawValue
	MessageTime   time.Time           `asn1:"generalized,explicit,optional,tag:0,omitempty"`
	ProtectionAlg AlgorithmIdentifier `asn1:"explicit,optional,tag:1,omitempty"`
	SenderKID     KeyIdentifier       `asn1:"explicit,optional,tag:2,omitempty"`
	RecipientKID  KeyIdentifier       `asn1:"explicit,optional,tag:3,omitempty"`
	TransactionID []byte              `asn1:"explicit,optional,tag:4,omitempty"`
	SenderNonce   []byte              `asn1:"explicit,optional,tag:5,omitempty"`
	RecipNonce    []byte              `asn1:"explicit,optional,tag:6,omitempty"`
	// FreeText      PKIFreeText         `asn1:"explicit,optional,tag:7,omitempty"` // Not working
	// GeneralInfo   []pkix.AttributeTypeAndValue `asn1:"explicit,optional,tag:8,omitempty"` // Not working
}

type PKIBody asn1.RawValue

type PKIProtection struct{ Bytes asn1.BitString }

type CMPCertificate any

/*
	CertStatus ::= SEQUENCE {
	   certHash    OCTET STRING,
	   certReqId   INTEGER,
	   statusInfo  PKIStatusInfo OPTIONAL
	}
*/
type CertStatus struct {
	CertHash  []byte
	CertReqID int
	// StatusInfo PKIStatusInfo `asn1:"explicit,optional,omitempty"` // Not working
}

/*
CertConfirmContent ::= SEQUENCE OF CertStatus
*/
type CertConfirmContent []CertStatus

/*
	      PKIMessage ::= SEQUENCE {
	         header           PKIHeader,
	         body             PKIBody,
	         protection   [0] PKIProtection OPTIONAL,
	         extraCerts   [1] SEQUENCE SIZE (1..MAX) OF CMPCertificate
	                          OPTIONAL
		  }
*/
type PKIMessage struct {
	Header     PKIHeader
	Body       asn1.RawValue
	Protection PKIProtection    `asn1:"optional,tag:0,omitempty"`
	ExtraCerts []CMPCertificate `asn1:"optional,tag:1,omitempty"`
}
