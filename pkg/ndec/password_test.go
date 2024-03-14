package ndec

import "testing"

func TestPasswordHash(t *testing.T) {
	password := []byte("abcdef")
	hash := PasswordHash(password)

	if hash != 0x24 {
		t.Errorf("Expected hash to be 0x24, but got %02x", hash)
	}
}
