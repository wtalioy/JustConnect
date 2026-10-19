package main

/*
#include <stdint.h>
*/
import "C"

import (
	"runtime"
	"sync"
	"unsafe"
)

type instance struct {
	payload []byte
	start   chan struct{}
	done    chan struct{}
	once    sync.Once
}

var (
	mu        sync.Mutex
	next      uint64
	instances = make(map[uint64]*instance)
)

//export jc_probe_abi
func jc_probe_abi() C.uint32_t { return 1 }

//export jc_probe_create
func jc_probe_create(input *C.uint8_t, length C.uint32_t) C.uint64_t {
	if length > 65536 || (input == nil && length != 0) {
		return 0
	}
	s := &instance{
		payload: C.GoBytes(unsafe.Pointer(input), C.int(length)),
		start:   make(chan struct{}),
		done:    make(chan struct{}),
	}
	go func() {
		<-s.start
		// Exercise retained Go memory after the caller has overwritten its input.
		runtime.GC()
		close(s.done)
	}()
	mu.Lock()
	defer mu.Unlock()
	next++
	instances[next] = s
	return C.uint64_t(next)
}

func (s *instance) wait() {
	s.once.Do(func() { close(s.start) })
	<-s.done
}

//export jc_probe_read
func jc_probe_read(handle C.uint64_t, output *C.uint8_t, capacity C.uint32_t, length *C.uint32_t) C.int32_t {
	if length == nil || capacity > 65536 || (output == nil && capacity != 0) {
		return -1
	}
	mu.Lock()
	defer mu.Unlock()
	s := instances[uint64(handle)]
	if s == nil {
		return -1
	}
	*length = C.uint32_t(len(s.payload))
	if capacity < *length {
		return -2
	}
	s.wait()
	copy(unsafe.Slice((*byte)(unsafe.Pointer(output)), int(capacity)), s.payload)
	return 0
}

//export jc_probe_destroy
func jc_probe_destroy(handle C.uint64_t) C.int32_t {
	mu.Lock()
	defer mu.Unlock()
	s := instances[uint64(handle)]
	if s == nil {
		return -1
	}
	s.wait()
	delete(instances, uint64(handle))
	return 0
}

//export jc_probe_live
func jc_probe_live() C.uint32_t {
	mu.Lock()
	defer mu.Unlock()
	return C.uint32_t(len(instances))
}

func main() {}
