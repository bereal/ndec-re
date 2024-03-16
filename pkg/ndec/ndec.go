package ndec

import "math/bits"

const gammaIters = 0x7d

func Gamma(password []byte) []byte {
	data := make([]byte, 0xff)
	copy(data, password)
	st1, st2 := 0xff^data[0], 0xff^data[1]
	i, j := 0, 2

	for k := -gammaIters; k < 0; k++ {
		st1--
		cur := 0xff ^ (data[j] - data[j+1]) ^ st1
		data[i] = cur
		i++
		j += 2

		st1 = bits.RotateLeft8(st1, k) ^ st2
		st2 = -(st2 << 1) - cur
		st1 += st2
	}

	return data
}

func GammaHash(gamma []byte) byte {
	var hash, state byte

	for _, b := range gamma {
		hash -= b
		state ^= hash
		hash = -hash - state
	}

	return hash
}

type Direction byte

const (
	Encode Direction = 1
	Decode Direction = 0xff // -1
)

func Round1(data, gamma []byte, encode Direction) {
	var xor, sum byte
	for _, b := range gamma {
		xor ^= b
		sum += b
	}
	sum *= byte(encode)

	for i, b := range data {
		switch i % 3 {
		case 0:
			data[i] = b ^ xor
		case 1:
			data[i] = b - sum
		case 2:
			data[i] = b + sum
		}
	}
}

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
