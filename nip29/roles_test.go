package nip29

import (
	"reflect"
	"testing"
)

func TestModerationPolicyRoles(t *testing.T) {
	p := ModerationPolicy{
		"moderator": {KindDeleteEvent, KindUpdatePinList},
		"admin":     {KindPutUser, KindRemoveUser},
		"viewer":    nil,
	}
	got := p.Roles(map[string]string{"admin": "runs the group"})
	want := []GroupRole{
		{Name: "admin", Description: "runs the group"},
		{Name: "moderator", Description: "may delete-event, update-pins"},
		{Name: "viewer"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Roles = %+v, want %+v", got, want)
	}
	if n := ModerationKindName(9999); n != "kind 9999" {
		t.Fatalf("unnamed kind: %q", n)
	}
}
