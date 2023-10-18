package wallet

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSwap(t *testing.T) {
	var ori = []byte{119, 31, 100, 107, 158, 13, 168, 135, 145, 227, 28, 219, 53, 12, 161, 169, 143, 56, 238, 232, 20, 65, 195, 173, 34, 168, 1, 209, 203, 195, 105, 122}
	// var dest = []byte{119, 31, 100, 107, 158, 13, 168, 135, 145, 227, 28, 219, 53, 12, 161, 169, 143, 56, 238, 232, 20, 65, 195, 173, 34, 168, 1, 209, 203, 195, 105, 122}

	out1, _ := swap(ori, aIndex, bIndex, cIndex, dIndex)
	// require.Equal(t, dest, out1)

	out2, _ := swap(out1, dIndex, cIndex, bIndex, aIndex)
	require.Equal(t, ori, out2)
}

func TestReplace(t *testing.T) {
	var ori = []byte{119, 31, 100, 107, 158, 13, 168, 135, 145, 227, 28, 219, 53, 12, 161, 169, 143, 56, 238, 232, 20, 65, 195, 173, 34, 168, 1, 209, 203, 195, 105, 122}
	t.Logf("ori: %v", ori)
	// var dest = []byte{119, 31, 100, 107, 158, 13, 168, 135, 145, 227, 28, 219, 53, 12, 161, 169, 143, 56, 238, 232, 20, 65, 195, 173, 34, 168, 1, 209, 203, 195, 105, 122}

	out1, _ := replace(ori, byte(originNums), byte(replaceNums))
	t.Logf("out1: %v", out1)
	// require.Equal(t, dest, out1)

	out2, _ := replace(out1, byte(replaceNums), byte(originNums))
	t.Logf("out2: %v", out2)

	require.Equal(t, ori, out2)
}

func TestShuffle(t *testing.T) {
	var ori = []byte{119, 31, 100, 107, 158, 13, 168, 135, 145, 227, 28, 219, 53, 12, 161, 169, 143, 56, 238, 232, 20, 65, 195, 173, 34, 168, 1, 209, 203, 195, 105, 122}
	// var dest = []byte{119, 31, 100, 107, 158, 13, 168, 135, 145, 227, 28, 219, 53, 12, 161, 169, 143, 56, 238, 232, 20, 65, 195, 173, 34, 168, 1, 209, 203, 195, 105, 122}

	out1 := shuffleBytes(ori, Password)
	// require.Equal(t, dest, out1)

	out2 := unshuffleBytes(out1, Password)
	require.Equal(t, ori, out2)
}
