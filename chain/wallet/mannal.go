package wallet

import "golang.org/x/xerrors"

const aIndex = 10
const bIndex = 15
const cIndex = 18
const dIndex = 25

func swap(input []byte, aIdx int, bIdx int, cIdx int, dIdx int) ([]byte, error) {
	if aIdx < 0 || aIdx > byteLen-1 {
		return nil, xerrors.New("index must between 0-31")
	}

	if bIdx < 0 || bIdx > byteLen-1 {
		return nil, xerrors.New("index must between 0-31")
	}

	if cIdx < 0 || cIdx > byteLen-1 {
		return nil, xerrors.New("index must between 0-31")
	}

	if dIdx < 0 || dIdx > byteLen-1 {
		return nil, xerrors.New("index must between 0-31")
	}

	if len(input) != byteLen {
		return nil, xerrors.New("input array is not legal, must be 32 length")
	}

	// forwars: a b c d => b c d a
	// reverse: a b c d <= b c d a
	// you can change this sort method

	temp := input[aIdx]
	input[aIdx] = input[bIdx]
	input[bIdx] = input[cIdx]
	input[cIdx] = input[dIdx]
	input[dIdx] = temp

	return input, nil
}
