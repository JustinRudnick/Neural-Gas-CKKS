package input

import (
	"math"
	"sort"

	"gonum.org/v1/gonum/mat"
)

type MinMaxScaler struct {
	Lo, Hi *mat.VecDense // per-feature bounds learned in Fit
}

func quantile(sorted []float64, q float64) float64 {
	pos := q * float64(len(sorted)-1)
	i := int(math.Floor(pos))
	if i >= len(sorted)-1 {
		return sorted[len(sorted)-1]
	}
	frac := pos - float64(i)
	return sorted[i]*(1-frac) + sorted[i+1]*frac
}

// Fit learns per-feature bounds. loQ=0, hiQ=1 gives plain min-max;
// e.g. 0.01 and 0.99 gives the outlier-robust variant.
func Fit(X []*mat.VecDense, loQ, hiQ float64) *MinMaxScaler {
	d := X[0].Len()
	lo, hi := mat.NewVecDense(d, nil), mat.NewVecDense(d, nil)
	col := make([]float64, len(X))
	for j := 0; j < d; j++ {
		for i, x := range X {
			col[i] = x.AtVec(j)
		}
		sort.Float64s(col)
		lo.SetVec(j, quantile(col, loQ))
		hi.SetVec(j, quantile(col, hiQ))
	}
	return &MinMaxScaler{Lo: lo, Hi: hi}
}

// TransformVec scales one sample into [0,1] and returns a new vector.
// Out-of-range values are clipped; constant features become 0.
func (s *MinMaxScaler) TransformVec(x *mat.VecDense) *mat.VecDense {
	d := x.Len()
	out := mat.NewVecDense(d, nil)
	for j := 0; j < d; j++ {
		lo := s.Lo.AtVec(j)
		r := s.Hi.AtVec(j) - lo
		if r == 0 {
			continue
		}
		out.SetVec(j, math.Min(1, math.Max(0, (x.AtVec(j)-lo)/r)))
	}
	return out
}

func (s *MinMaxScaler) Transform(X []*mat.VecDense) []*mat.VecDense {
	out := make([]*mat.VecDense, len(X))
	for i, x := range X {
		out[i] = s.TransformVec(x)
	}
	return out
}
