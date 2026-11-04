package input

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type CSVFile struct {
	File     *os.File
	scanner  *bufio.Scanner
	Cols     int
	ColNames []string
	Split    string
	Trim     string
}

func NewCSVFile(file *os.File, hasHead bool, split string, trim string) (csv *CSVFile, err error) {
	if file == nil {
		return nil, errors.New("file is nil")
	}

	scanner := bufio.NewScanner(file)

	count := 0
	var firstLine string = ""
	if hasHead && scanner.Scan() {
		firstLine = scanner.Text()
		count = strings.Count(firstLine, split)
	}

	names := strings.Split(firstLine, split)

	csv = &CSVFile{
		scanner:  scanner,
		File:     file,
		Cols:     count,
		ColNames: names,
		Split:    split,
		Trim:     trim,
	}

	return csv, nil
}

func NewCSVFiles(hasHead bool, split string, trim string, files []*os.File) (csv []*CSVFile, err error) {
	csv = make([]*CSVFile, len(files))
	for i := range files {
		csv[i], err = NewCSVFile(files[i], hasHead, split, trim)
		if err != nil {
			return nil, fmt.Errorf("Creating CSV files failed: %w", err)
		}
	}
	return csv, nil
}

func (csv *CSVFile) Scan() bool {
	return csv.scanner.Scan()
}

func (csv *CSVFile) ReadLine() (floats []float64, err error) {
	var input string = ""
	if csv.scanner.Scan() {
		input = csv.scanner.Text()
	}
	var elems []string = strings.Split(input, csv.Split)
	floats = make([]float64, len(elems))

	for i, elem := range elems {
		floats[i], err = strconv.ParseFloat(strings.Trim(elem, csv.Trim), 64)
		if err != nil {
			return nil, fmt.Errorf("Could not parse element: %w", err)
		}
	}

	return floats, nil
}

func SlicePrint[T any](elems []T) {
	print("[")
	for _, el := range elems {
		print(el, ", ")
	}
	println("]")
}
