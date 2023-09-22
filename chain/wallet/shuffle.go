package wallet

import (
	"crypto/sha256"
)

const Password = "xxxxxxxxxx"

func unshuffleBytes(input []byte, key string) []byte {
	if len(input) != 32 {
		panic("Input length must be 32 bytes")
	}

	output := make([]byte, 32)
	for i, pos := range generateArrayFromKey(Password) {
		output[pos] = input[i]
	}
	return output
}

func shuffleBytes(input []byte, key string) []byte {
	if len(key) != 10 {
		return input
	} else {
		if len(input) != 32 {
			panic("Input length must be 32 bytes")
		}

		output := make([]byte, 32)
		for i, pos := range generateArrayFromKey(key) {
			output[i] = input[pos]
		}
		return output
	}
}

func generateArrayFromKey(key string) [32]int {
	if len(key) != 10 {
		panic("Key must be 10 characters long")
	}

	hash := sha256.Sum256([]byte(key))
	var numbers [32]int
	var isUsed [32]bool

	for i, v := range hash {
		modValue := int(v & 0b011111)

		// Ensure the value is unique
		for isUsed[modValue] {
			modValue = (modValue + 1) & 0b011111
		}

		numbers[i] = modValue
		isUsed[modValue] = true
	}

	return numbers
}
