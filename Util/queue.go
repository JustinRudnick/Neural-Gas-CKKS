package util

import (
	"fmt"
	"sync"
)

type Queue[T any] struct {
	size  int
	slice []T
	mu    sync.Mutex
}

func NewQueue[T any]() *Queue[T] {

	return &Queue[T]{
		size:  0,
		slice: make([]T, 0),
		mu:    sync.Mutex{},
	}

}

func (q *Queue[T]) Size() int {
	return q.size
}

func (q *Queue[T]) Push(elem T) {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.slice = append(q.slice, elem)
	q.size++
}

func (q *Queue[T]) Pop() (firstElem T, err error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.size == 0 {
		return firstElem, fmt.Errorf("Queue is empty.")
	}
	firstElem = q.slice[0]
	q.slice = q.slice[1:]
	q.size--
	return firstElem, nil
}

func (q *Queue[T]) Seek(idx int) (elem T, err error) {
	if q.size <= idx {
		return elem, fmt.Errorf("index %d out of range for length [%d]", idx, q.size)
	}
	return q.slice[idx], nil
}

func (q *Queue[T]) Peek(idx int) (firstElem T, err error) {
	return q.Seek(0)
}

func (q *Queue[T]) Clear() {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.slice = q.slice[:]
	q.size = 0
}
