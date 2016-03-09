package openpgp

import (
	"os"
	"testing"

	"github.com/keybase/go-crypto/openpgp/armor"
	"github.com/keybase/go-crypto/openpgp/packet"
)

func parseKeyFile(t *testing.T, name string) {
	f, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	b, err := armor.Decode(f)
	if err != nil {
		t.Fatal(err)
	}

	p, err := packet.Read(b.Body)
	if err != nil {
		t.Fatal(err)
	}

	priv, ok := p.(*packet.PrivateKey)
	if !ok {
		t.Fatal("didn't parse a private key")
	}

	if priv.PubKeyAlgo != packet.PubKeyAlgoECDSA {
		t.Fatal("not an ecdsa key")
	}
}

func TestParseP256r1(t *testing.T) {
	parseKeyFile(t, "testdata/brainpoolP256r1.pgp")
}

func TestParseP384r1(t *testing.T) {
	parseKeyFile(t, "testdata/brainpoolP384r1.pgp")
}

func TestParseP512r1(t *testing.T) {
	parseKeyFile(t, "testdata/brainpoolP512r1.pgp")
}
