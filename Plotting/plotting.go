package plotting

import (
	"fmt"
	"log"

	"gonum.org/v1/gonum/mat"
	"gonum.org/v1/plot"
	"gonum.org/v1/plot/plotter"
	"gonum.org/v1/plot/vg"
)

// plots the passed dataset <vecs> onto a 2 dimensional canvas within the interval of coordinates x, y in [0, 1]
func Plot2D(vecs []*mat.VecDense, title string, filename string) {
	p := plot.New()

	p.X.Min = 0
	p.X.Max = 1
	p.Y.Min = 0
	p.Y.Max = 1

	p.Title.Text = title
	p.X.Label.Text = "X"
	p.Y.Label.Text = "Y"

	var points plotter.XYs = make([]plotter.XY, len(vecs))

	for i, vec := range vecs {
		points[i] = plotter.XY{X: vec.AtVec(0), Y: vec.AtVec(1)}
	}

	scatter, err := plotter.NewScatter(points)
	if err != nil {
		log.Fatal(err)
	}

	p.Add(scatter)

	if err := p.Save(6*vg.Inch, 6*vg.Inch, fmt.Sprintf("%s.png", filename)); err != nil {
		log.Fatal(err)
	}

}

func Plot3D(vecs []*mat.VecDense, title string, filename string) {
	p := plot.New()

	p.Title.Text = title
	p.X.Label.Text = "X"
	p.Y.Label.Text = "Y"

	var points plotter.XYZs = make([]plotter.XYZ, len(vecs))

	for i, vec := range vecs {
		points[i] = plotter.XYZ{X: vec.AtVec(0), Y: vec.AtVec(1), Z: vec.AtVec(2)}
	}

	scatter, err := plotter.NewScatter(points)
	if err != nil {
		log.Fatal(err)
	}

	p.Add(scatter)

	if err := p.Save(6*vg.Inch, 4*vg.Inch, fmt.Sprintf("%s.png", filename)); err != nil {
		log.Fatal(err)
	}

}
