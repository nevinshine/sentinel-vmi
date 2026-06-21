package main

import (
	"context"
	"fmt"
	"reflect"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
)

func main() {
	// 1. Create a tracer
	tracer := otel.Tracer("test-tracer")

	// 2. Start a span
	ctx, _ := tracer.Start(context.Background(), "test-span")

	// 3. Extract the TraceID
	span := trace.SpanFromContext(ctx)
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
			
			// If it's the span, let's look inside
			if field.Type.String() == "trace.Span" {
				spanVal := val.Field(i)
				fmt.Printf("  Span Type: %v\n", spanVal.Type())
			}
		}
	}
}
