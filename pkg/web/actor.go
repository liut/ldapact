package web

import "context"

type actorKey struct{}

// WithActor attaches the logged-in bind DN to the request context. The authn
// middleware sets it on every authenticated request so page rendering can
// show "Logged in as <DN>" in the header.
func WithActor(ctx context.Context, actor string) context.Context {
	return context.WithValue(ctx, actorKey{}, actor)
}

// ActorFrom returns the logged-in bind DN attached by the middleware, or ""
// when the request is not authenticated.
func ActorFrom(ctx context.Context) string {
	s, _ := ctx.Value(actorKey{}).(string)
	return s
}
