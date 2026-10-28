package nip02

import (
	"reflect"
	"testing"

	"github.com/ohstr/nmilat/nip01"
)

func TestFollowUnfollow(t *testing.T) {
	old := &nip01.Event{Kind: KindContacts, Content: "{}", Tags: [][]string{{"p", "aa", "wss://r", "alice"}}}
	out, added := Follow(old, "AA", "BB")
	if !reflect.DeepEqual(added, []string{"bb"}) || !reflect.DeepEqual(Follows(out), []string{"aa", "bb"}) {
		t.Fatalf("%v %v", added, out.Tags)
	}
	// The petname and relay of an existing entry survive.
	if !reflect.DeepEqual(out.Tags[0], []string{"p", "aa", "wss://r", "alice"}) || out.Content != "{}" {
		t.Fatalf("%+v", out)
	}
	out, removed := Unfollow(out, "aa")
	if !reflect.DeepEqual(removed, []string{"aa"}) || !reflect.DeepEqual(Follows(out), []string{"bb"}) {
		t.Fatalf("%v %v", removed, out.Tags)
	}
	if out.Kind != KindContacts {
		t.Fatal(out.Kind)
	}
}
