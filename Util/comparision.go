package util

import (
	"fmt"
	"math"
)

type Number interface {
	int | uint | uint64 | float32 | float64
}

func Max[number Number](values []number) (max number, err error) {
	if len(values) == 0 {
		return number(math.NaN()), fmt.Errorf("input vector is empty.")
	}

	res := float64(values[0])
	for i := 1; i < len(values); i++ {
		res = math.Max(res, float64(values[i]))
	}
	return number(res), nil
}

func Abs[number Number](values []number) (abs []number) {
	abs = make([]number, len(values))
	for i := range values {
		abs[i] = number(math.Abs(float64(values[i])))
	}
	return abs
}

/*
Adds up the passed function's output based on the input values
*/
func Sum[number Number](values []number, addElem func(value number, idx int) number) (sum number) {
	sum = number(0)
	for i, value := range values {
		sum += addElem(value, i)
	}
	return sum
}

/*
Adds up the input values.
*/
func SumElems[number Number](values []number) (sum number) {
	return Sum(values, func(value number, idx int) number { return value })
}

/*
Multiplies up the passed function's output based on the input values
*/
func Prod[number Number](values []number, prodElem func(value number, idx int) number) (prod number) {
	prod = number(1)
	for i, value := range values {
		prod *= prodElem(value, i)
	}
	return prod
}

/*
Adds up the input values.
*/
func ProdElems[number Number](values []number) (prod number) {
	return Prod(values, func(value number, idx int) number { return value })
}

func ProdAny[In any, Out Number](values []In, prodElem func(value In, idx int) Out) (prod Out) {
	prod = Out(1)
	for i, value := range values {
		prod *= prodElem(value, i)
	}
	return prod
}

func SumAny[In any, Out Number](values []In, addElem func(value In, idx int) Out) (sum Out) {
	sum = Out(0)
	for i, value := range values {
		sum += addElem(value, i)
	}
	return sum
}

/*
returns the first index of the passed element within the passed slice or -1 if the element is not within the slice.
*/
func In[In comparable](slice []In, elem In) int {
	for i, e := range slice {
		if e == elem {
			return i
		}
	}
	return -1
}
