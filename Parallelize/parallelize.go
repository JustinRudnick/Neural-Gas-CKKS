package parallelize

import (
	"math"
	"runtime"
	"sync"
)

/*
Splits the passed slice [items] into [maxCores] sub-slices of (as good as possible) equal length.

Blocks until all goroutines are done.

Calls [runtime.SetDefaultGOMAXPROCS] in the end.
*/
func MultiThread[K, T any](item K, items []T, maxCores int, function func(item K, subSlice []T, originalStartIndex int, wg *sync.WaitGroup)) {
	runtime.GOMAXPROCS(int(math.Min(float64(maxCores), float64(runtime.NumCPU()))))
	var wg sync.WaitGroup

	itemCount := len(items)
	routineCount := int(math.Min(float64(maxCores), float64(itemCount)))
	smallSubSliceSize := int(math.Floor(float64(itemCount) / float64(routineCount)))
	bigSubSliceSize := smallSubSliceSize + 1

	wg.Add(routineCount)

	rest := itemCount % routineCount

	for i := range rest {
		offset := i * bigSubSliceSize
		go function(item, items[offset:offset+bigSubSliceSize], offset, &wg)
	}

	for i := range routineCount - 1 - rest {
		offset := i*smallSubSliceSize + rest*bigSubSliceSize
		go function(item, items[offset:offset+smallSubSliceSize], offset, &wg)
	}

	offset := (routineCount-1)*smallSubSliceSize + rest
	function(item, items[offset:], offset, &wg)

	wg.Wait()
	runtime.SetDefaultGOMAXPROCS()
}
