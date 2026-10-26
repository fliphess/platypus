package web

import (
	"context"
	"time"

	"platypus/internal/appstate"
	"platypus/internal/authz"
	"platypus/internal/db"
	"platypus/internal/session"
)

// Viewer is the logged-in user of a request, with everything that decides
// what they may do.
type Viewer struct {
	User    db.User
	Session session.Session
	State   appstate.State
	Subject authz.Subject
	now     time.Time
}

// InAdminMode reports whether the viewer is an admin who confirmed admin
// mode with a second factor.
func (v *Viewer) InAdminMode() bool {
	return v.User.IsAdmin && v.Session.InAdminMode(v.now)
}

type viewerKey struct{}

func withViewer(ctx context.Context, v *Viewer) context.Context {
	return context.WithValue(ctx, viewerKey{}, v)
}

// viewerFrom returns the viewer of the request. Every route behind the
// identity middleware has one.
func viewerFrom(ctx context.Context) *Viewer {
	v, _ := ctx.Value(viewerKey{}).(*Viewer)
	return v
}
