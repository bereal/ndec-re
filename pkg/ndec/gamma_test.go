package ndec

import (
	"encoding/hex"
	"regexp"
	"testing"
)

func TestGamma(t *testing.T) {
	password := []byte("password")
	gamma := Gamma(password)

	expected := cleanupHex(`
		71cbefc12baa7a7fe7dc9d9f7e71173f7db435ee196a5e7397ff16
		ce4e305b2606974f5637f780350036ecb4aa0c9b1b9f9d268a6d9a
		26ab042895b48958621da069826c60fdd36ebb1d84506309c0c78d
		69ab86c7176036a57d742af74530a4fd6d4908e22eff8d2b6edaca
		a3a380a16211bb2240d103cb3a4f2cb396
	`)

	h := hex.EncodeToString(gamma[:gammaIters])
	if h != cleanupHex(expected) {
		t.Errorf("Expected gamma to be %s, but got %s", expected, h)
	}
}

func TestHash(t *testing.T) {
	data := []byte("password")

	gamma := Gamma(data)
	hash := GammaHash(gamma)

	if hash != 0xac {
		t.Errorf("Expected hash to be 0xac, but got %02x", hash)
	}
}

func cleanupHex(s string) string {
	return regexp.MustCompile(`[^0-9a-fA-F]`).ReplaceAllString(s, "")
}

func TestApplyGamma(t *testing.T) {
	gamma := Gamma([]byte("password"))
	data := []byte("test")
	ApplyGamma(data, gamma)
	expected := `647f5964`
	if hex.EncodeToString(data) != expected {
		t.Errorf("Expected data to be %s, but got %s", expected, hex.EncodeToString(data))
	}
}
