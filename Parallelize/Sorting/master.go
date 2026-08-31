package sorting

import (
	"fmt"
	"math"
	"runtime"
	"sync"
	util "threadedBubbleSort/Util"
)

type Master[T any] struct {
	workers *util.Queue[*Worker[T]]
	slice   []T
	locks   map[*T]*sync.Mutex
	wg      *sync.WaitGroup
}

/*
amount of workers = maxCores - 1
*/
func NewMaster[T any](slice []T, sections, maxCores int) (master *Master[T], err error) {
	sectionCount := int(math.Min(float64(sections), float64(len(slice))))

	locks := make(map[*T]*sync.Mutex, sections)
	master = &Master[T]{
		workers: util.NewQueue[*Worker[T]](),
		slice:   slice,
		locks:   locks,
		wg:      &sync.WaitGroup{},
	}

	var largeSectionSize, largeSectionCount int
	var smallSectionSize, smallSectionCount int

	if sectionCount > 0 {
		smallSectionSize = len(slice) / sectionCount
	} else {
		smallSectionSize = 0
	}
	largeSectionSize = smallSectionSize + 1
	if sectionCount > 0 {
		largeSectionCount = len(slice) % sectionCount
	} else {
		largeSectionCount = sectionCount
	}
	if smallSectionSize > 0 {
		smallSectionCount = (len(slice) - largeSectionCount*largeSectionSize) / smallSectionSize
	} else {
		smallSectionCount = 0
	}

	for i := range largeSectionCount {
		master.locks[&slice[i*largeSectionSize]] = &sync.Mutex{}
	}
	offset := largeSectionCount * largeSectionSize
	for i := range smallSectionCount {
		master.locks[&slice[i*smallSectionSize+offset]] = &sync.Mutex{}
	}

	for range maxCores - 1 {
		master.workers.Push(NewWorker(master, master.wg))
	}

	return master, nil
}

/*
Locks the mutex and
returns a pointer to the [sync.Mutex] needed to work in this section or [nil] if no new section begins.
*/
func (m *Master[T]) GetLock(addr *T) *sync.Mutex {
	mutex := m.locks[addr]
	if mutex != nil {
		mutex.Lock()
		return mutex
	}
	return nil
}

func (m *Master[T]) TryGetLock(addr *T) *sync.Mutex {
	mutex := m.locks[addr]
	if mutex != nil {
		mutex.TryLock()
		return mutex
	}
	return nil
}

func (m *Master[T]) AddWorker(worker *Worker[T]) {
	m.workers.Push(worker)
}

/*
k ...only sort until the first k elements are ascending
*/
func (m *Master[T]) BubbleSort(sortElem func(slice []T, i, j int) (err error), k ...int) (err error) {
	defaultCores := runtime.GOMAXPROCS(0)
	defer runtime.GOMAXPROCS(defaultCores)
	runtime.GOMAXPROCS(m.workers.Size())

	var loops int = len(m.slice) - 1
	if len(k) > 0 {
		loops = int(math.Min(float64(k[0]), float64(loops)))
	}

	if m.workers.Size() <= 1 {
		return Bubblesort(m.slice, loops, sortElem)
	}

	var errchan = make(chan error, 1)
	var worker *Worker[T]
	startIdx := len(m.slice) - 2
	runLen := len(m.slice) - 1
	for range loops {
		worker = m.nextWorker()

		m.wg.Add(1)
		go worker.OneBubble(m.slice, m.GetLock(&m.slice[0]), startIdx, runLen, errchan, sortElem)

	}

	m.wg.Wait()

	select {
	case err = <-errchan: // non blocking
		return fmt.Errorf("Bubblesort failed: %w", err)
	default:
	}

	return err
}

func (m *Master[T]) BubbleSortPhased(sortElem func(slice []T, i, j int) (err error)) (err error) {
	if m.workers.Size() <= 1 {
		return Bubblesort(m.slice, len(m.slice), sortElem)
	}

	defaultCores := runtime.GOMAXPROCS(0)
	defer runtime.GOMAXPROCS(defaultCores)
	runtime.GOMAXPROCS(m.workers.Size())

	maxWorkers := m.workers.Size()
	println("maxWorkers: ", maxWorkers)

	for i := range len(m.slice) {
		m.sortOnePhase(m.slice, i%2, maxWorkers, sortElem) //WARNING probably wrong: slice[i:] //should work
		m.wg.Wait()
	}

	return nil
}

func (m *Master[T]) sortOnePhase(slice []T, phase, maxWorkers int, sortElem func(slice []T, i, j int) (err error)) {
	var slots int
	var longRunSize, longRunCount int
	var shortRunSize, shortRunCount int

	slots = (len(slice) - phase) / 2

	print("sortOnePhase: ")
	util.PrintSlice[T, string](slice, func(elem T, idx int) string { return fmt.Sprint(elem) })

	//TODO how to compute them correctly?
	if slots > 0 {
		shortRunSize = slots / int(math.Min(float64(slots), float64(maxWorkers)))
	} else {
		shortRunSize = 0
	}
	longRunSize = shortRunSize + 1 //correct
	if shortRunSize > 0 {
		longRunCount = slots % shortRunSize //TODO len(slice) % (2 * slots) OR (len(slice)/2) % slots ?
	} else {
		longRunCount = slots
	}
	if shortRunSize > 0 {
		shortRunCount = (slots - longRunCount*longRunSize) / shortRunSize
	} else {
		shortRunCount = 0
	}

	fmt.Println("sortOnePhase:")
	println("slots: ", slots)
	fmt.Printf("\tlongRunCount: %d, longRunSize: %d\n", longRunCount, longRunSize)
	fmt.Printf("\tshortRunCount: %d, shortRunSize: %d\n", shortRunCount, shortRunSize)

	var errchan = make(chan error, 1)
	var worker *Worker[T]
	for i := range longRunCount {
		worker = m.nextWorker()

		startIdx := len(slice) - 2 - 2*i*longRunSize - phase
		m.wg.Add(1)
		println("worker starts at idx: ", startIdx)
		worker.OneSwapPhased(slice, startIdx, longRunSize, errchan, sortElem)
	}

	offset := 2 * longRunCount * longRunSize
	for i := range shortRunCount {
		worker = m.nextWorker()

		startIdx := len(slice) - 2 - offset - 2*i*shortRunSize - phase
		m.wg.Add(1)
		println("worker starts at idx: ", startIdx)
		worker.OneSwapPhased(slice, startIdx, shortRunSize, errchan, sortElem)
	}

	print("sortOnePhase end: ")
	util.PrintSlice[T, string](slice, func(elem T, idx int) string { return fmt.Sprint(elem) })
}

func (m *Master[T]) nextWorker() (worker *Worker[T]) {
	for { //wait, until worker is available
		if m.workers.Size() > 0 {
			worker, _ = m.workers.Pop()
			break
		}
	}
	return worker
}

/*
common bubble sort
*/
func Bubblesort[T any](slice []T, k int, sortElem func(slice []T, i, j int) (err error)) (err error) {
	loops := int(math.Min(float64(len(slice)-1), float64(k)))
	for i := range loops {
		for j := len(slice) - 2; j >= i; j-- {
			err = sortElem(slice, j, j+1)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
