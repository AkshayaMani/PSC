package par

import(
    "go.dedis.ch/kyber"
    "go.dedis.ch/kyber/proof"
)

// Map over a slices of Elgamal Ciphers with the given parallel for-loop.
func MapElgamalCiphers(loop ParallelForLoop, f func([2]kyber.Point, [2]kyber.Point, kyber.Point) ([2]kyber.Point, [2]kyber.Point, proof.Prover), x [][2]kyber.Point, y [][2]kyber.Point, Y kyber.Point, n int) ([][2]kyber.Point, [][2]kyber.Point, []proof.Prover) {
        xbar := make([][2]kyber.Point, n)
        ybar := make([][2]kyber.Point, n)
        proof := make([]proof.Prover, n)

        loop(0, uint(n), 1, func(id uint) {
                xbar[id], ybar[id], proof[id] = f(x[id], y[id], Y)
        })

        return xbar, ybar, proof
}

// Convenience function: use MapElgamalCiphers with a chunking parallel for loop.
func MapElgamalCiphersChunked(f func([2]kyber.Point, [2]kyber.Point, kyber.Point) ([2]kyber.Point, [2]kyber.Point, proof.Prover), x [][2]kyber.Point, y [][2]kyber.Point, Y kyber.Point, n int) ([][2]kyber.Point, [][2]kyber.Point, []proof.Prover) {
        return MapElgamalCiphers(ForChunked, f, x, y, Y, n)
}

// Map over a slice of Strings with the given parallel for-loop.
func MapString(loop ParallelForLoop, f func(uint) string, l int) []string {
        result := make([]string, l)

        loop(0, uint(l), 1, func(idx uint) {
                result[idx] = f(idx)
        })

	return result
}

// Convenience function: use MapString with a chunking parallel for loop.
func MapStringChunked(f func(uint) string, l int) []string {
        return MapString(ForChunked, f, l)
}

// Convenience function: use MapString with an interleaving parallel for loop.
func MapStringInterleaved(f func(uint) string, l int) []string {
        return MapString(ForInterleaved, f, l)
}

// Map over a slice of float64s with the given parallel for-loop.
func MapFloat64(loop ParallelForLoop, f func(float64) float64, l []float64) []float64 {
	result := make([]float64, len(l))

	loop(0, uint(len(l)), 1, func(idx uint) {
		result[idx] = f(l[idx])
	})

	return result
}

// Convenience function: use MapFloat64 with a chunking parallel for loop.
func MapFloat64Chunked(f func(float64) float64, l []float64) []float64 {
	return MapFloat64(ForChunked, f, l)
}

// Convenience function: use MapFloat64 with an interleaving parallel for loop.
func MapFloat64Interleaved(f func(float64) float64, l []float64) []float64 {
	return MapFloat64(ForInterleaved, f, l)
}

func max(l, r uint) uint {
	if l > r {
		return l
	}

	return r
}

func min(l, r uint) uint {
	if l < r {
		return l
	}

	return r
}
