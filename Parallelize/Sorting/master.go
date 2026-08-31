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
	if sections > len(slice) {
		return master, fmt.Errorf("cannot fragment a slice of length %d into %d sections (too many sections).", len(slice), sections)
	}

	locks := make(map[*T]*sync.Mutex, sections)
	master = &Master[T]{
		workers: util.NewQueue[*Worker[T]](),
		slice:   slice,
		locks:   locks,
		wg:      &sync.WaitGroup{},
	}

	var largeSectionSize, largeSectionCount int
	var smallSectionSize, smallSectionCount int

	smallSectionSize = len(slice) / sections
	largeSectionSize = smallSectionSize + 1
	largeSectionCount = len(slice) % sections
	smallSectionCount = (len(slice) - largeSectionCount*largeSectionSize) / smallSectionSize

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
		for i := range loops {
			for j := len(m.slice) - 2; j >= i; j-- {
				err = sortElem(m.slice, j, j+1)
				if err != nil {
					return err
				}
			}
		}
		return nil
	}

	var errchan = make(chan error, 1)
	var worker *Worker[T]
	startIdx := len(m.slice) - 2
	runLen := len(m.slice) - 1
	for range loops {
		for { //wait, until worker is available
			if m.workers.Size() > 0 {
				worker, _ = m.workers.Pop()
				break
			}
			// println("MASTER: waits for worker")
			// time.Sleep(500)
		}
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

// TODO ai Version umsetzen
func (m *Master[T]) BubbleSortPhased(sortElem func(slice []T, i, j int) (err error)) (err error) {
	defaultCores := runtime.GOMAXPROCS(0)
	defer runtime.GOMAXPROCS(defaultCores)
	runtime.GOMAXPROCS(m.workers.Size())

	for i := range len(m.slice) - 1 {
		m.sortOnePhase(m.slice[i:], sortElem) //WARNING probably wrong: slice[i:] //should work
		m.wg.Wait()
	}

	return nil
}

func (m *Master[T]) sortOnePhase(slice []T, sortElem func(slice []T, i, j int) (err error)) {
	var slots int
	var longRunSize, longRunCount int
	var shortRunSize, shortRunCount int
	if len(m.slice)%2 == 0 { //even phase
		slots = len(slice) / 2
	} else { //odd phase
		slots = (len(slice) - 1) / 2
	}

	shortRunSize = slots / m.workers.Size()
	longRunSize = shortRunSize + 1
	longRunCount = len(slice) % slots
	shortRunCount = (slots - longRunCount*longRunSize) / shortRunSize

	var errchan = make(chan error, 1)
	var worker *Worker[T]
	for i := range longRunCount {
		worker = m.nextWorker()

		startIdx := len(slice) - 2 - i*longRunSize
		m.wg.Add(1)
		worker.OneSwapPhased(slice, startIdx, longRunSize, errchan, sortElem)
	}

	offset := longRunCount * longRunSize
	for i := range shortRunCount {
		worker = m.nextWorker()

		startIdx := len(slice) - 2 - offset - i*shortRunSize
		m.wg.Add(1)
		worker.OneSwapPhased(slice, startIdx, shortRunSize, errchan, sortElem)
	}
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
