package ndec

import (
	"encoding/hex"
	"regexp"
	"testing"
)

func TestGamma(t *testing.T) {
	t.Run("generate gamma", func(t *testing.T) {
		password := []byte("password")
		gamma := Gamma(password)

		expected := cleanupHex(`
			71cbefc12baa7a7fe7dc9d9f7e71173f7db435ee196a5e7397ff16
			ce4e305b2606974f5637f780350036ecb4aa0c9b1b9f9d268a6d9a
			26ab042895b48958621da069826c60fdd36ebb1d84506309c0c78d
			69ab86c7176036a57d742af74530a4fd6d4908e22eff8d2b6edaca
			a3a380a16211bb2240d103cb3a4f2cb396
		`)

		checkBin(t, gamma[:gammaIters], expected)
	})

	t.Run("gamma hash", func(t *testing.T) {
		data := []byte("password")
		gamma := Gamma(data)
		hash := GammaHash(gamma)

		if hash != 0xac {
			t.Errorf("Expected hash to be 0xac, but got %02x", hash)
		}
	})
}

func TestPasswordHash(t *testing.T) {
	password := []byte("abcdef")
	hash := PasswordHash(password)

	if hash != 0x24 {
		t.Errorf("Expected hash to be 0x24, but got %02x", hash)
	}
}

func TestEncryption(t *testing.T) {
	t.Run("round 1", func(t *testing.T) {
		gamma := Gamma([]byte("password"))
		data := []byte("test")
		Round1(data, gamma, Encode)
		checkBin(t, data, "647f5964")

		Round1(data, gamma, Decode)
		if string(data) != "test" {
			t.Errorf("Expected decoded data to be test, but got %s", data)
		}
	})

	t.Run("round 2", func(t *testing.T) {
		data := []byte{0x64, 0x7f, 0x59, 0x64, 0x3a, 0xf3, 0x1a}
		gamma := Gamma([]byte("password"))
		Round2(data, gamma, 0x45, 0x24)
		checkBin(t, data, "1d7014a15cc018")
	})

	t.Run("round 3", func(t *testing.T) {
		data := []byte{0x1d, 0x70, 0x14, 0xa1, 0x5c, 0xc0, 0x18}
		gamma := Gamma([]byte("password"))
		Round3(data, []byte("abcdef"), GammaHash(gamma))
		checkBin(t, data, "166c449c279df2")
	})
}

func checkBin(t *testing.T, data []byte, expected string) {
	expected = cleanupHex(expected)
	encoded := hex.EncodeToString(data)
	if encoded != expected {
		t.Errorf("Expected data to be %s, but got %s", expected, encoded)
	}
}

func cleanupHex(s string) string {
	return regexp.MustCompile(`[^0-9a-fA-F]`).ReplaceAllString(s, "")
}
