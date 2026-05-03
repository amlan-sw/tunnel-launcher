package main

import "runtime"

// runtimeGOOS is exposed as a variable so tests can override it.
var runtimeGOOS = runtime.GOOS
