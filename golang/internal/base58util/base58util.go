package base58util

import (
	"errors"
	"math/big"
)

const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

var alphabetIndex = func() map[rune]int {
	result := make(map[rune]int, len(alphabet))
	for index, value := range alphabet {
		result[value] = index
	}
	return result
}()

// Encode encodes bytes with the Bitcoin base58 alphabet.
func Encode(input []byte) string {
	if len(input) == 0 {
		return ""
	}
	value := new(big.Int).SetBytes(input)
	base := big.NewInt(58)
	zero := big.NewInt(0)
	mod := new(big.Int)
	encoded := make([]byte, 0, len(input)*2)
	for value.Cmp(zero) > 0 {
		value.DivMod(value, base, mod)
		encoded = append(encoded, alphabet[mod.Int64()])
	}
	for _, b := range input {
		if b != 0 {
			break
		}
		encoded = append(encoded, alphabet[0])
	}
	for left, right := 0, len(encoded)-1; left < right; left, right = left+1, right-1 {
		encoded[left], encoded[right] = encoded[right], encoded[left]
	}
	return string(encoded)
}

// Decode decodes Bitcoin base58 text.
func Decode(input string) ([]byte, error) {
	if input == "" {
		return []byte{}, nil
	}
	base := big.NewInt(58)
	value := big.NewInt(0)
	for _, char := range input {
		index, ok := alphabetIndex[char]
		if !ok {
			return nil, errors.New("invalid base58 character")
		}
		value.Mul(value, base)
		value.Add(value, big.NewInt(int64(index)))
	}
	decoded := value.Bytes()
	leadingZeros := 0
	for _, char := range input {
		if char != rune(alphabet[0]) {
			break
		}
		leadingZeros++
	}
	if leadingZeros == 0 {
		return decoded, nil
	}
	result := make([]byte, leadingZeros+len(decoded))
	copy(result[leadingZeros:], decoded)
	return result, nil
}
