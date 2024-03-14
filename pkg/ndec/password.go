package ndec

func PasswordHash(password []byte) byte {
	data := make([]byte, 0xff)
	copy(data, password)

	var hash, state byte

	for _, b := range data {
		hash += b
		state -= hash
		hash ^= state
		state ^= 0xff
	}

	return hash
}
