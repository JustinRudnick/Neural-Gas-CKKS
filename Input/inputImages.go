package input

import (
	"image"
	"image/jpeg"
	"image/png"
	"os"
	"strings"
)

// returns the image or nil if the image could not be processed
func GetImage(imagePath string) *image.Image {
	dotIdx := strings.LastIndex(imagePath, ".")
	format := imagePath[dotIdx+1:]

	switch strings.ToLower(format) {
	case "png":
		return GetPng(imagePath)
	case "jpg", "jpeg":
		return GetJpeg(imagePath)
	default:
		return nil
	}
}

func GetJpeg(imagePath string) *image.Image {
	file, err := os.Open(imagePath)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	img, err := jpeg.Decode(file)
	if err != nil {
		panic(err)
	}

	return &img
}

func GetPng(imagePath string) *image.Image {
	file, err := os.Open(imagePath)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	img, err := png.Decode(file)
	if err != nil {
		panic(err)
	}

	return &img
}
