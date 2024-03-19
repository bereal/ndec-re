package ndec

import (
	"math/bits"
)

const gammaIters = 0x7d

type NDEC struct {
	gamma     []byte
	gammaHash byte
	pw2       []byte
	pw2Hash   byte
}

func New(password1, password2 []byte) *NDEC {
	gamma := Gamma(password1)

	return &NDEC{
		gamma:     gamma,
		gammaHash: GammaHash(gamma),
		pw2:       password2,
		pw2Hash:   PasswordHash(password2),
	}
}

func (n *NDEC) Encrypt(data []byte, iv byte) {
	Round1(data, n.gamma, Encrypt)
	Round2(data, n.gamma, iv, n.pw2Hash, Encrypt)
	Round3(data, n.pw2, n.gammaHash, Encrypt)
}

func (n *NDEC) Decrypt(data []byte) []byte {
	iv, data := data[0], data[1:]
	Round3(data, n.pw2, n.gammaHash, Decrypt)
	Round2(data, n.gamma, iv, n.pw2Hash, Decrypt)
	Round1(data, n.gamma, Decrypt)
	return data
}

func Gamma(password []byte) []byte {
	data := make([]byte, 0xff)
	copy(data, password)
	st1, st2 := 0xff^data[0], 0xff^data[1]
	i, j := 0, 2

	for k := gammaIters; k > 0; k-- {
		st1--
		cur := 0xff ^ (data[j] - data[j+1]) ^ st1
		data[i] = cur
		i++
		j += 2

		st1 = ror8(st1, k) ^ st2
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

type Direction = byte

const (
	Encrypt Direction = 1
	Decrypt Direction = 0xff
)

func Round1(data, gamma []byte, dir Direction) {
	var xor, sum byte
	for _, b := range gamma {
		xor ^= b
		sum += b
	}
	sum *= dir

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

func Round2(data, gamma []byte, iv, pwHash byte, dir Direction) {
	ctr := len(data)
	gi := 0
	for i, b := range data {
		x := gamma[gi]
		if x == 0 {
			x, gi = gamma[0], 0
		}
		gi++

		x += pwHash
		if dir == Encrypt {
			b = ((b ^ iv) + x) ^ x - x
			b = ror8(b, ctr)
		} else {
			b = rol8(b, ctr)
			b = ((b + x) ^ x - x) ^ iv
		}

		iv = ror8(iv, ctr)
		data[i] = b
		ctr--
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

func Round3(data, password []byte, gammaHash byte, dir Direction) {
	ctr := len(data)
	password = append(password, 0)
	for i, b := range data {
		p := password[i%len(password)]
		if dir == Encrypt {
			b = -((b - p) ^ p) - p - gammaHash
		} else {
			b = (-b - p - gammaHash) ^ p + p
		}

		data[i] = b
		gammaHash = (-ror8(gammaHash, ctr)) ^ p
		ctr--
	}
}

func ror8(b byte, n int) byte {
	return bits.RotateLeft8(b, -(n & 7))
}

func rol8(b byte, n int) byte {
	return bits.RotateLeft8(b, n&7)
}
