# nilerrwrap

Flags `return ..., fmt.Errorf("...%w...", err)` where `err` can be nil on the
path reaching the call (fmt.Errorf never returns nil, so the success path
reports an error). Handles `%w`, and `%v`/`%s` on error-typed operands.

    go run github.com/dogukanturhal/platform-shared/tools/analyzers/nilerrwrap/cmd/nilerrwrap@<tag> ./...

This is a nested Go module (own go.mod) so the shared library does not depend
on golang.org/x/tools. Release tags: tools/analyzers/nilerrwrap/vX.Y.Z.

Run it inside each service module (services are separate modules in go.work).
Heuristics: call results are treated as possibly nil unless the callee is
fmt.Errorf, errors.New, context.Context.Err, or named New*/Err*.
