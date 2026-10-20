//go:build cgo && !jc_abi_test

package main

import "github.com/wtalioy/JustConnect/corelib/internal/bridge"

var engine = bridge.New(nil)

const testDriver = false
