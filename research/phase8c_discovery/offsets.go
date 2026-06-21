package main

import (
	"fmt"
	"net/http"
	"reflect"
	"unsafe"
)

func main() {
	var r http.Request
	fmt.Printf("Method offset: %d\n", unsafe.Offsetof(r.Method))
	fmt.Printf("URL offset: %d\n", unsafe.Offsetof(r.URL))
	fmt.Printf("Host offset: %d\n", unsafe.Offsetof(r.Host))
	
	// Get context field offset using reflect since it is unexported
	rt := reflect.TypeOf(r)
	ctxField, _ := rt.FieldByName("ctx")
	fmt.Printf("ctx offset: %d\n", ctxField.Offset)
	fmt.Printf("Sizeof Request: %d\n", unsafe.Sizeof(r))
}
