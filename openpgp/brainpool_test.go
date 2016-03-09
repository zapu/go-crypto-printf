package openpgp

import (
	"bytes"
	"crypto"
	"os"
	"strings"
	"testing"

	"github.com/keybase/go-crypto/openpgp/packet"
)

const msg = "Hello World!"

func signWithKeyFile(t *testing.T, name, password string) {
	f, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	es, err := ReadArmoredKeyRing(f)
	if err != nil {
		t.Fatal(err)
	}

	// Cycle through all entities we find a signing key.
	for _, e := range es {
		if err = e.PrivateKey.Decrypt([]byte(password)); err != nil {
			continue
		}

		buf := new(bytes.Buffer)
		if err = DetachSign(buf, e, strings.NewReader(msg), nil); err == nil {
			p, err := packet.Read(buf)
			if err != nil {
				t.Fatal(err)
			}
			sig, ok := p.(*packet.Signature)
			if !ok {
				t.Fatal("couldn't parse signature from buffer")
			}
			signed := crypto.SHA256.New()
			signed.Write([]byte(msg))
			if err := e.PrimaryKey.VerifySignature(signed, sig); err != nil {
				t.Fatal(err)
			}

			break
		}
	}
	if err != nil {
		t.Fatal(err)
	}
}

func TestParseP256r1(t *testing.T) {
	signWithKeyFile(t, "testdata/brainpoolP256r1.pgp", "256")
}

func TestParseP384r1(t *testing.T) {
	signWithKeyFile(t, "testdata/brainpoolP384r1.pgp", "384")
}

func TestParseP512r1(t *testing.T) {
	signWithKeyFile(t, "testdata/brainpoolP512r1.pgp", "512")
}
