package nip34

import (
	"errors"
	"testing"

	"github.com/ohstr/nmilat/nip01"
)

func TestNewGraspServerListAndParse(t *testing.T) {
	ev := NewGraspServerList(ownerPubkey, []string{"wss://grasp1.example", "wss://grasp2.example"})
	ev = signed(t, ev)

	gl, err := ParseGraspServerList(ev)
	if err != nil {
		t.Fatalf("ParseGraspServerList() error = %v", err)
	}
	if len(gl.Servers) != 2 || gl.Servers[0] != "wss://grasp1.example" {
		t.Errorf("Servers = %v", gl.Servers)
	}

	if err := ValidateGraspServerList(ev); err != nil {
		t.Errorf("ValidateGraspServerList() error = %v", err)
	}
}

func TestNewGraspServerList_Empty(t *testing.T) {
	ev := NewGraspServerList(ownerPubkey, nil)
	ev = signed(t, ev)

	gl, err := ParseGraspServerList(ev)
	if err != nil {
		t.Fatalf("ParseGraspServerList() error = %v", err)
	}
	if len(gl.Servers) != 0 {
		t.Errorf("Servers = %v, want empty", gl.Servers)
	}
}

func TestParseGraspServerList_WrongKind(t *testing.T) {
	ev := &nip01.Event{Kind: 1}
	if _, err := ParseGraspServerList(ev); !errors.Is(err, ErrWrongKind) {
		t.Errorf("error = %v, want ErrWrongKind", err)
	}
}
