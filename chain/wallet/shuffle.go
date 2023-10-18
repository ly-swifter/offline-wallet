package wallet

import (
	"crypto/sha256"
)

const Password = "xxxxxxxxxx"

const byteLen = 32

func shuffleBytes(input []byte, key string) []byte {
	if len(key) != 10 {
		return input
	} else {
		if len(input) != byteLen {
			panic("Input length must be 32 bytes")
		}

		output := make([]byte, byteLen)
		for i, pos := range generateArrayFromKey(key) {
			output[i] = input[pos]
		}

		out1, err := swap(output, aIndex, bIndex, cIndex, dIndex)
		if err != nil {
			log.Panicf("swap panic %s", err.Error())
		}

		out2, err := replace(out1, byte(originNums), byte(replaceNums))
		if err != nil {
			log.Panicf("replace panic %s", err.Error())
		}

		return out2
	}
}

func unshuffleBytes(input []byte, key string) []byte {
	if len(input) != byteLen {
		panic("Input length must be 32 bytes")
	}

	output := make([]byte, byteLen)
	for i, pos := range generateArrayFromKey(Password) {
		output[pos] = input[i]
	}

	out1, err := swap(output, dIndex, cIndex, bIndex, aIndex)
	if err != nil {
		log.Panicf("swap panic %s", err.Error())
	}

	out2, err := replace(out1, byte(replaceNums), byte(originNums))
	if err != nil {
		log.Panicf("replace panic %s", err.Error())
	}

	return out2
}

func generateArrayFromKey(key string) [32]int {
	if len(key) != 10 {
		panic("Key must be 10 characters long")
	}

	hash := sha256.Sum256([]byte(key))
	var numbers [byteLen]int
	var isUsed [byteLen]bool

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
