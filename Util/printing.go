package util

import "fmt"

func PrintSlice[In, Out any](slice []In, printableElement func(elem In, idx int) Out) {
	fmt.Printf("[")
	for i, elem := range slice {
		print(printableElement(elem, i))
		if i != len(slice)-1 {
			print(", ")
		}
	}
	fmt.Printf("]\n")
}

func SprintSlice[In, Out any](slice []In, printableElement func(elem In, idx int) Out) string {
	var s string = "["
	for i, elem := range slice {
		s += fmt.Sprint(printableElement(elem, i))
		if i != len(slice)-1 {
			s += (", ")
		}
	}
	s += "]"
	return s
}
