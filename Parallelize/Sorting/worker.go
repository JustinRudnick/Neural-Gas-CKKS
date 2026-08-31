package sorting

import (
	util "NeuralGasCKKS/Util"
	"fmt"
	"sync"
)

type Worker[T any] struct {
	m  *Master[T]
	wg *sync.WaitGroup
}

func NewWorker[T any](m *Master[T], wg *sync.WaitGroup) *Worker[T] {
	return &Worker[T]{
		m:  m,
		wg: wg,
	}
}

func (w *Worker[T]) TaskRun() {

}

func (w *Worker[T]) OneBubble(slice []T, lock *sync.Mutex, startIdx, runLen int, errchan chan error, sortElem func(slice []T, i, j int) (err error)) {
	// fmt.Printf("worker %p with master %p", w, w.m)
	// fmt.Printf(" using WaitGroup %p\n", w.wg)
	defer w.wg.Done()
	locks := util.NewQueue[*sync.Mutex]()
	locks.Push(lock)

	var newLock *sync.Mutex
	idx := startIdx
	for range runLen {
		if newLock = w.m.GetLock(&slice[idx]); newLock != nil { //lock
			locks.Push(newLock)
		}

		err := sortElem(slice, idx, idx+1)
		select {
		case errchan <- fmt.Errorf("OneBubble failed: %w", err): // non blocking
		default:
		}

		idx--

		if locks.Size() > 1 {
			doneLock, _ := locks.Pop()
			doneLock.Unlock()
		}

	}

	for range locks.Size() {
		doneLock, _ := locks.Pop()
		doneLock.Unlock()
	}

	// fmt.Printf("worker %p completed its task\n", w)
	w.TaskDone()

}

/*
adds the worker back in the [util.Queue] of it's [Master]
*/
func (w *Worker[T]) TaskDone() {
	w.m.AddWorker(w)
}
