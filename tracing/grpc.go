// SPDX-License-Identifier: Apache-2.0

package tracing

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// GRPCUnaryServerInterceptor creates a gRPC unary server interceptor for trace propagation
func GRPCUnaryServerInterceptor(serviceName string) grpc.UnaryServerInterceptor {
	tracer := otel.Tracer(serviceName)

	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		// Extract trace context from gRPC metadata
		md, ok := metadata.FromIncomingContext(ctx)
		if ok {
			ctx = otel.GetTextMapPropagator().Extract(ctx, &metadataCarrier{md: &md})
		}

		// Start a new span
		ctx, span := tracer.Start(
			ctx,
			info.FullMethod,
			trace.WithSpanKind(trace.SpanKindServer),
			trace.WithAttributes(
				attribute.String("rpc.system", "grpc"),
				attribute.String("rpc.service", info.FullMethod),
			),
		)
		defer span.End()

		// Call handler
		resp, err := handler(ctx, req)
		// Record error if any
		if err != nil {
			span.RecordError(err)
			span.SetAttributes(attribute.String("error", err.Error()))
		}

		return resp, fmt.Errorf("GRPCUnaryServerInterceptor: %w", err)
	}
}

// GRPCUnaryClientInterceptor creates a gRPC unary client interceptor for trace propagation
func GRPCUnaryClientInterceptor(serviceName string) grpc.UnaryClientInterceptor {
	tracer := otel.Tracer(serviceName)

	return func(
		ctx context.Context,
		method string,
		req, reply interface{},
		cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker,
		opts ...grpc.CallOption,
	) error {
		// Start a new span
		ctx, span := tracer.Start(
			ctx,
			method,
			trace.WithSpanKind(trace.SpanKindClient),
			trace.WithAttributes(
				attribute.String("rpc.system", "grpc"),
				attribute.String("rpc.service", method),
			),
		)
		defer span.End()

		// Inject trace context into gRPC metadata
		md := metadata.New(nil)
		otel.GetTextMapPropagator().Inject(ctx, &metadataCarrier{md: &md})
		ctx = metadata.NewOutgoingContext(ctx, md)

		// Call invoker
		err := invoker(ctx, method, req, reply, cc, opts...)
		// Record error if any
		if err != nil {
			span.RecordError(err)
			span.SetAttributes(attribute.String("error", err.Error()))
		}

		return fmt.Errorf("GRPCUnaryClientInterceptor: %w", err)
	}
}

// metadataCarrier implements TextMapCarrier for gRPC metadata
type metadataCarrier struct {
	md *metadata.MD
}

func (mc *metadataCarrier) Get(key string) string {
	values := mc.md.Get(key)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func (mc *metadataCarrier) Set(key string, value string) {
	mc.md.Set(key, value)
}

func (mc *metadataCarrier) Keys() []string {
	keys := make([]string, 0, len(*mc.md))
	for k := range *mc.md {
		keys = append(keys, k)
	}
	return keys
}
