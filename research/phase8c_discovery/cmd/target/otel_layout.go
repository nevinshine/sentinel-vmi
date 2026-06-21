package main

import (
	"context"
	"fmt"
	"reflect"
	"unsafe"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/sdk/trace"
	api_trace "go.opentelemetry.io/otel/trace"
)

func main() {
	// 1. Create a real tracer provider
	tp := trace.NewTracerProvider()
	otel.SetTracerProvider(tp)
	tracer := tp.Tracer("test-tracer")

	// 2. Start a span
	ctx, _ := tracer.Start(context.Background(), "test-span")

	// 3. Extract the TraceID
	span := api_trace.SpanFromContext(ctx)
	fmt.Printf("TraceID: %s\n", span.SpanContext().TraceID().String())

	// 4. Explore the context memory layout!
	// ctx is an interface{}. Underneath, it's a pointer to an internal OTel struct.
	// We want to find the exact offset to the TraceID [16]byte array.
	
	val := reflect.ValueOf(ctx)
	fmt.Printf("Context Type: %v\n", val.Type())
	
	// Let's traverse the reflect value to find the TraceID
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}
	fmt.Printf("Context Underlying Kind: %v\n", val.Kind())
	
	if val.Kind() == reflect.Struct {
		for i := 0; i < val.NumField(); i++ {
			field := val.Type().Field(i)
			fmt.Printf("Field %d: %s (%v) at offset %d\n", i, field.Name, field.Type, field.Offset)
			
			if field.Name == "val" {
				// Bypass unexported field restriction
				valPtr := unsafe.Pointer(val.Field(i).UnsafeAddr())
				valInterface := *(*interface{})(valPtr)
				spanVal := reflect.ValueOf(valInterface)
				fmt.Printf("  val Underlying Type: %v (Kind: %v)\n", spanVal.Type(), spanVal.Kind())
				if spanVal.Kind() == reflect.Ptr {
					spanVal = spanVal.Elem()
					for j := 0; j < spanVal.NumField(); j++ {
						spanField := spanVal.Type().Field(j)
						fmt.Printf("    Span Field %d: %s (%v) at offset %d\n", j, spanField.Name, spanField.Type, spanField.Offset)
						
						if spanField.Type.String() == "trace.SpanContext" {
							scVal := spanVal.Field(j)
							for k := 0; k < scVal.NumField(); k++ {
								scField := scVal.Type().Field(k)
								fmt.Printf("      SpanContext Field %d: %s (%v) at offset %d\n", k, scField.Name, scField.Type, scField.Offset)
							}
						}
					}
				}
			}
		}
	}
}
