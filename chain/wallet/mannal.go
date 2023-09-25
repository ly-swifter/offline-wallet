package wallet

import "golang.org/x/xerrors"

const aIndex = 10
const bIndex = 15

func swap(input []byte, aIdx int, bIdx int) ([]byte, error) {
	if aIdx < 0 || aIdx > byteLen-1 {
		return nil, xerrors.New("index must between 0-31")
	}

	if bIdx < 0 || bIdx > byteLen-1 {
		return nil, xerrors.New("index must between 0-31")
	}

	if len(input) != byteLen {
		return nil, xerrors.New("input array is not legal, must be 32 length")
	}

	swapc := input[aIdx]
	input[aIdx] = input[bIdx]
	input[bIdx] = swapc

	return input, nil
}
