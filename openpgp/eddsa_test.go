package openpgp

import (
	"bytes"
	"io"
	"io/ioutil"
	"strings"
	"testing"

	"github.com/keybase/go-crypto/openpgp/armor"
	"github.com/keybase/go-crypto/openpgp/clearsign"
	"github.com/keybase/go-crypto/openpgp/packet"
)

const ed25519SecretKey = `-----BEGIN PGP PRIVATE KEY BLOCK-----

lFgEWLlH5hYJKwYBBAHaRw8BAQdAZok35G7RiRPTVW+V4B6+cS6B0YTHoCdiZ65o
GLXR8pAAAP4qdiV8Ib+oJfhikpP4k81Lse0uhiKztT+i8VbCf7f8CRIPtB5FZERT
QSBLZXliYXNlIGdvLWNyeXB0byB0ZXN0ZXKIeQQTFggAIQUCWLlH5gIbAwULCQgH
AgYVCAkKCwIEFgIDAQIeAQIXgAAKCRBGOGQrdSAHN7jKAQCrAZLd1DfOsLRHfLqs
2/n1HlX55I7G6aG70Nmp+IFcQAEAoRJcdiSWVLAzXbYpKb3QOl2THqbQScfkKZ6D
NyJqNA4=
=HtLj
-----END PGP PRIVATE KEY BLOCK-----
`

func TestEd25519RoundTrip(t *testing.T) {
	testString := "test okokokokokok"

	entities, err := ReadArmoredKeyRing(strings.NewReader(ed25519SecretKey))
	if err != nil {
		t.Fatalf("error opening keys: %v", err)
	}
	if len(entities) != 1 {
		t.Fatal("expected only 1 key")
	}
	if !entities[0].PrimaryKey.PubKeyAlgo.CanSign() {
		t.Fatal("key cannot sign")
	}
	buf := new(bytes.Buffer)
	err = ArmoredDetachSign(buf, entities[0], bytes.NewBufferString(testString), nil)

	block, err := armor.Decode(buf)
	if err != nil {
		t.Fatalf("error decoding resulting armor: %v", err)
	}
	reader := packet.NewReader(block.Body)
	pkt, err := reader.Next()
	if err != nil {
		t.Fatalf("error reading armored signature: %v", err)
	}

	sig, ok := pkt.(*packet.Signature)
	if !ok {
		t.Fatalf("signature did not parse")
	}

	hash := sig.Hash.New()
	io.Copy(hash, bytes.NewBufferString(testString))

	err = entities[0].PrimaryKey.VerifySignature(hash, sig)
	if err != nil {
		t.Fatalf("verify signature failed with: %v", err)
	}
}

func TestEd25519BitLength(t *testing.T) {
	entities, _ := ReadArmoredKeyRing(strings.NewReader(ed25519SecretKey))
	bitLen, err := entities[0].PrimaryKey.BitLength()
	if err != nil {
		t.Fatalf("error in BitLength(): %v", err)
	}
	if bitLen != 256 {
		t.Fatalf("Got BitLength %v expected 256", bitLen)
	}
}

// Clearsigned message for key that we own.
const clearSignPayload = `-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

OpenPGP is the most widely used email encryption standard. It is
defined by the OpenPGP Working Group of the Internet Engineering 
Task Force (IETF) as a Proposed Standard in RFC 4880. OpenPGP was
originally derived from the PGP software, created by Phil Zimmermann.
-----BEGIN PGP SIGNATURE-----

iF4EARYIAAYFAli5X9EACgkQRjhkK3UgBze3fgEAg84Kcps0b70/6tMqc5TgslCJ
UeS5HBl7HiKTtkPykCcBALQOjckckdBz6KxAhKxmjOJ8qxcbx30Ye2A7nYtyohoI
=lv2c
-----END PGP SIGNATURE-----
`

// Clearsigned message (altered), signature is invalid
const clearSignPayloadInvalid = `-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

Chancellor on brink of second bailout for banks
-----BEGIN PGP SIGNATURE-----

iF4EARYIAAYFAli5WNAACgkQRjhkK3UgBzdK4AEA/iTUhqia9hlAjzbfhG1Y5IQF
XkvWqK865ABexLnGDSAA/2Z5QWG4PUqLQZl5fY5Zuv452e4NWqY35uUCxYw/eHEB
=kaTQ
-----END PGP SIGNATURE-----
`

// Clearsigned message for different key
const clearSignPayloadNoKey = `-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

Hello World!
-----BEGIN PGP SIGNATURE-----

iF4EARYIAAYFAli5YNYACgkQH8B3H/TuEEdFsQEAzTu7RlxmXuZXn4ZDrGHDmm+O
3wNPA6jXWCOw8raTQMgA/22jmf9Zje25p10p1ULpMfHiCBwabu5u6GFVrWwk9xsG
=qh4w
-----END PGP SIGNATURE-----
`

func readKeysAndCheckSig(clearsigned string, t *testing.T) (err error) {
	block, _ := clearsign.Decode(bytes.NewBufferString(clearsigned).Bytes())

	entities, err := ReadArmoredKeyRing(strings.NewReader(ed25519SecretKey))
	if err != nil {
		t.Fatalf("error opening keys: %v", err)
	}

	_, err = CheckDetachedSignature(entities, bytes.NewBuffer(block.Bytes), block.ArmoredSignature.Body)
	return err
}

func TestEd25519VerifyClearSign(t *testing.T) {
	err := readKeysAndCheckSig(clearSignPayload, t)
	if err != nil {
		t.Fatalf("error checking signature: %v", err)
	}
}

func TestEd25519VerifyClearSignInvalid(t *testing.T) {
	err := readKeysAndCheckSig(clearSignPayloadInvalid, t)
	if err == nil {
		t.Fatalf("verification should fail!")
	}
}

func TestEd25519VerifyClearSignNoKey(t *testing.T) {
	err := readKeysAndCheckSig(clearSignPayloadNoKey, t)
	if err == nil {
		t.Fatalf("we should not be able to verify this!")
	}
}

const ed25519SecretKey2 = `-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: Keybase OpenPGP v2.0.62
Comment: https://keybase.io/crypto

xVgEWL2HOBYJKwYBBAHaRw8BAQdAo/2zlJuTrEnuQfJ9lY426d/lmRCj59fW9qsH
o8cm0sQAAQAc3JJBD/+Gnqbki1lI2yQvKfjxVmNYbyfE00gu4fWrnRDGzQhNciBS
b2JvdMJ2BBMWCgAeBQJYvYc4AhsDAwsJBwMVCggCHgECF4ADFgIBAhkBAAoJEFJQ
62zQlkZ7fOYBAE7Nr5FTel2I5iHaQdjp6s4UJz1lteFrdZUE3IVQl5w+AQBrH1fK
0Na5Llgtc9k5iZTls+GnFd84brwhEOnvRQgGDMddBFi9hzgSCisGAQQBl1UBBQEB
B0Cs0O+HtIDGHoEODZgtlTyAZRqooN8y9OLWekeU6zIwXwMBCgkAAQBBxWlsZA1v
deRgZPOs5e+jAJp6KJjZ97C6rxf0lnr4dhI1wmcEGBYKAA8FAli9hzgFCQ8JnAAC
GwgACgkQUlDrbNCWRntHTAEAYRzOLqzcVRJ+NzSIkf2OIKW+NN+2D0oWNqVKOQ+c
xZcBAC0hkbCMFNAb+B2iyZgtmsAT9jJOS2c6xnwBnE2UnzIE
=krA2
-----END PGP PRIVATE KEY BLOCK-----

`

func TestEd25519SerializeKey(t *testing.T) {
	// Check if we can export private key, armor it and then re-import.
	// Exporting requires us to sign identities and subkeys properly.
	// If either signing or veryfing does not work, re-importing will fail.

	entities, err := ReadArmoredKeyRing(strings.NewReader(ed25519SecretKey2))
	if err != nil {
		t.Fatalf("error opening keys: %v", err)
	}

	var buf bytes.Buffer
	err = entities[0].SerializePrivate(&buf, nil)
	if err != nil {
		t.Fatal(err)
	}

	armored, err := rawToArmored(buf.Bytes(), true)
	if err != nil {
		t.Fatal(err)
	}

	entities, err = ReadArmoredKeyRing(strings.NewReader(armored))
	if err != nil {
		t.Fatal(err)
	}
}

const edPgpMessage = `-----BEGIN PGP MESSAGE-----
Version: Keybase OpenPGP v2.0.62
Comment: https://keybase.io/crypto

wV4D8QSbkho4bZYSAQdAbraKkqPG11yMGlCAOVmMFCuGkCkMuv9tmkhP/7A77kAw
JcITivZTs+yPI2IvjVmAZldB4Y2kOJTRxgjZGQq27Ht9kwSAkRPFt+VYvMB55Te8
0r0BwQnNaqtqw1CgjMMV73JQvTFPu3yAqOvvgTfjPTqc8+tsLO+CQje0bdShaZOL
EqaxQ3rLnZfIMlKsxww5WNwvoKvQqIg+FoRUAt2rbwlIxYaZYS7+Fy6XES2zUMjU
XMEpuopz7NmP2SkVC3t+tFUpf6LZPDGHNyN8ipkTaOTYOPXGwnHxx/v6A+Mqem8c
RsjkLnDJvlLkWvcwC0Hotet7AHO09IMVnYlBCAM/bVXeCGaHy5OOEVai7g7Q8zM=
=TeLt
-----END PGP MESSAGE-----

`

func TestEd25519ReadMessage(t *testing.T) {
	const expectedStr = "looks like its working"

	entities, err := ReadArmoredKeyRing(strings.NewReader(ed25519SecretKey2))
	if err != nil {
		t.Fatalf("error opening keys: %v", err)
	}

	block, err := armor.Decode(bytes.NewBufferString(edPgpMessage))
	if err != nil {
		t.Fatalf("error decoding resulting armor: %v", err)
	}
	md, err := ReadMessage(block.Body, entities, nil, nil)
	if err != nil {
		t.Fatalf("error in ReadMessage: %v", err)
	}

	if !md.IsSigned {
		t.Fatalf("message should have been signed")
	}

	if md.SignedBy.PrivateKey != entities[0].PrivateKey {
		t.Fatalf("SignedBy is not our key")
	}

	if md.DecryptedWith.PrivateKey != entities[0].Subkeys[0].PrivateKey {
		t.Fatalf("DecryptedWith is not our key")
	}

	contents, err := ioutil.ReadAll(md.UnverifiedBody)
	if string(contents) != expectedStr {
		t.Errorf("bad plain text got:\"%s\" want:\"%s\"", string(contents), expectedStr)
	}
}

// Ed25519 primary key with invalid public key P.
const invalidEddsaKey = `-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: Keybase OpenPGP v2.0.64
Comment: https://keybase.io/crypto

xVcEWL66QxYJKwYBBAHaRw8BAP9AxKu8stVAKQFSmqFS9Ix3XfRZnuZiFfNfduJy
lgrt8AABAJ/s+wHmKnN4iTlrk8afUnOdznirfbZslbAWvklnySiBENXNCE1yIFJv
Ym90wnYEExYKAB4FAli+ukMCGwMDCwkHAxUKCAIeAQIXgAMWAgECGQEACgkQBMA5
Uo2Ksvy4uwEAofpazp4hZKl9getVyv9ohWNCsJO5SVhLlWIeUgudz/MBAKDf1Ul4
03ghKYQrp8BBtSZgkRywS1CzIsPM+TKOxxUAx10EWL66QxIKKwYBBAGXVQEFAQEH
QKf3w8hdmDeN4Nwx0shYse7/RokTcGJa9P119ZzbwYcMAwEKCQABABTL6gnhVNdb
gBCcJ9PMS6b2Am8iPmt68FvsYGWiT8/XEFzCZwQYFgoADwUCWL66QwUJDwmcAAIb
CAAKCRAEwDlSjYqy/Nh9AQB5/qReBLkVsPOdyGLLH2xhuSvEqc2BoIsbBLaxjSDO
4gEAw4bB8qGi8FTdXTCfL3C2cb893Rr5MOzbuBFIyOUJqgs=
=CUjI
-----END PGP PRIVATE KEY BLOCK-----

`

// Ed25519 primary key with invalid (30-byte) private key seed.
const invalidEddsaKey2 = `-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: Keybase OpenPGP v2.0.64
Comment: https://keybase.io/crypto

xVYEWL7DEBYJKwYBBAHaRw8BAQdAxwd4z4dCXJe4iQfDvPlAOPQ0RBRu7sU9yib1
ovjrC3AAAPDO28O0PDSOrfeS+1ZtUUAwpsSd0OoDFORz3y+4t/QSY80ITXIgUm9i
b3TCdgQTFgoAHgUCWL7DEAIbAwMLCQcDFQoIAh4BAheAAxYCAQIZAQAKCRAqJY4s
j028sOBTAQAlBHmc4n7Gp4Oggg/t8bFNFUYROaacCq0wBDYiTUI/5wEA/oQ+y6UG
TlPrwBB1eN9n16To5TtfuRL1ULxGIy971ADHXQRYvsMQEgorBgEEAZdVAQUBAQdA
5p3gCAuHatK1qwSgbwZ1rdXocP+WmHGiZIjxlkDVhg0DAQoJAAEAbPQnac6koq2z
/UHAprfr0x1rdMi83fUBIFkpfg4m1wsRB8JnBBgWCgAPBQJYvsMQBQkPCZwAAhsI
AAoJEColjiyPTbywv+4BAIa4FCGRZmMZpIW88a0wU0jV6cCw4FVCJSBRzPrN4pz9
AQCR7HWES/PlR1gh33cgHCaCgaVt7TajaSCsj2VmC4StAA==
=jAMh
-----END PGP PRIVATE KEY BLOCK-----

`

func TestEd25519InvalidKeys(t *testing.T) {
	const expectedStr = "looks like its working"

	_, err := ReadArmoredKeyRing(strings.NewReader(invalidEddsaKey))
	if err == nil {
		t.Fatalf("key should not parse")
	}

	_, err = ReadArmoredKeyRing(strings.NewReader(invalidEddsaKey2))
	if err == nil {
		t.Fatalf("key should not parse")
	}
}
