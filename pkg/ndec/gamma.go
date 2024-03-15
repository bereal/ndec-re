package ndec

import "math/bits"

const gammaIters = 0x7d

func RotateRight(b byte, n uint) byte {
	n = n & 7
	if n == 0 {
		return b
	}

	return b>>n | b<<(8-n)
}

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

func ApplyGamma(data, gamma []byte) {
	var xor, sum byte
	for _, b := range gamma {
		xor ^= b
		sum += b
	}

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
