package nip13

import (
	"context"
	"encoding/hex"
	"runtime"
	"sync"
	"testing"
	"time"
)

const (
	privateKey = "0acd12cbf0fb87cd13b17bc9b57dffd11b3870b407984cec5a4ce2a69b90268c"
	publicKey  = "3c1db3dd55e2ff09ba5317dd8eec2339797e9e2ddf74591172735c47f3a2ad6e"
)

func TestNip13Zeros(t *testing.T) {

	tests := map[string]int{}
	tests["0000ed29b31e087cc6953e593adc6805968e5b426692eb7117ede1d9cec353fe"] = 16
	tests["2d9ed7e7f0c737b24d475b1f4ee72d6cd3bee14d2b7d4f4dfdb040a139f535b5"] = 2
	tests["00010373361cb87966cc0ee880d462ae71c0035ef160830b660db4c04043e02e"] = 15
	tests["00a1a49e206dd01ab8e55ed2ddaa0845b3dd0ab7a0b6cf87fc1e839b9110841f"] = 8
	tests["1FFF0373361CB87966CC0EE880D462AE71C0035EF160830B660DB4C04043E02E"] = 3
	tests["7FFF0373361CB87966CC0EE880D462AE71C0035EF160830B660DB4C04043E02E"] = 1
	tests["FFFF0373361CB87966CC0EE880D462AE71C0035EF160830B660DB4C04043E02E"] = 0
	// 0000000

	for eventID, expCount := range tests {
		count, err := countZerosFromHex(eventID)
		if err != nil {
			t.Fatal(err)
		}

		if count != expCount {
			t.Fatalf("counter mismatch: expected %d, got %d", expCount, count)
		}
	}
}

func newFields(kind int, pubkey, content string, tags ...[]string) Fields {
	return Fields{
		Kind:      kind,
		PubKey:    pubkey,
		Tags:      tags,
		CreatedAt: uint64(time.Now().Unix()),
		Content:   content,
	}
}

func TestNip13Check(t *testing.T) {
	tests := []struct {
		fields    func() Fields
		wantError bool
	}{
		{
			func() Fields {
				ev := newFields(1,
					"34f0bc5b341219600b129396db7c2fa926eb0024310d71cbd61eee186167dafd",
					"🇯🇵 明けましておめでとうございます！ 🎊",
					[]string{"nonce", "680169", "2"},
				)
				ev.CreatedAt = 1672510247
				ev.ID = "321f3beeb623a746b699439df6527cceb3162a7086a45916467ba24859839cd9"
				return ev
			},
			false,
		},
		{
			func() Fields {
				ev := newFields(1,
					"9a3465f82693dd281cb4512a9a650e9be43bf2006be40d636caf84483d5cef40",
					"🎉🇼🇫 BONNE ANNÉE! 🇼🇫 🎉",
					[]string{"nonce", "423960", "2"},
				)
				ev.CreatedAt = 1672519478
				ev.ID = "3a0d102fd3a223e0aef3964943b2335c74f1b6c52a65c81a501fa2b06385ca54"
				return ev
			},
			false,
		},
		{
			func() Fields {
				ev := newFields(1, publicKey, "", []string{"nonce", "67204", "2"})
				ev.ID = "0d9ed7e7f0c737b24d475b1f4ee72d6cd3bee14d2b7d4f4dfdb040a139f535b5"
				return ev
			},
			true,
		},
		{
			func() Fields {
				ev := newFields(1,
					"9a3465f82693dd281cb4512a9a650e9be43bf2006be40d636caf84483d5cef40",
					"Hello",
					[]string{"client", "555", ""},
					[]string{"h", "o", "", "2"},
					[]string{"nonce", "11129", "15"},
				)
				ev.CreatedAt = 1672519479
				ev.ID = "00010373361cb87966cc0ee880d462ae71c0035ef160830b660db4c04043e02e"
				return ev
			},
			false,
		},
		{
			func() Fields {
				ev := newFields(1,
					"9a3465f82693dd281cb4512a9a650e9be43bf2006be40d636caf84483d5cef40",
					"Hello",
					[]string{"nonce", "11129", "15"},
					[]string{"client", "555", ""},
					[]string{"h", "o", "", "2"},
				)
				ev.CreatedAt = 1672519479
				ev.ID = "00010373361cb87966cc0ee880d462ae71c0035ef160830b660db4c04043e02e"
				return ev
			},
			true,
		},
	}

	for _, test := range tests {
		t.Run("test", func(t *testing.T) {

			ev := test.fields()
			if _, _, err := ValidatePow(ev); err != nil && !test.wantError {
				t.Fatal(err)
			}

		})
	}
}

func TestNip13Mine(t *testing.T) {

	tests := []struct {
		fields     func() Fields
		difficulty int
		nonce      string
		eventID    string
	}{
		{
			func() Fields {
				ev := newFields(1,
					"34f0bc5b341219600b129396db7c2fa926eb0024310d71cbd61eee186167dafd",
					"🇯🇵 明けましておめでとうございます！ 🎊",
					[]string{"p", "9a3465f82693dd281cb4512a9a650e9be43bf2006be40d636caf84483d5cef40"},
					[]string{"client", "n555"},
				)
				ev.CreatedAt = 1672510247
				return ev
			},
			5,
			"12",
			"012487db6b813e6dc5d799ab1829f6c061f880aedc25bcc2e0e559d6b17de25a",
		}, {
			func() Fields {
				ev := newFields(1,
					"9a3465f82693dd281cb4512a9a650e9be43bf2006be40d636caf84483d5cef40",
					"🎉🇼🇫 BONNE ANNÉE! 🇼🇫 🎉",
				)
				ev.CreatedAt = 1672519478
				return ev
			},
			2,
			"0",
			"171e7ce46d472da23ad9b8083244935b74470661e722d7b4756b136fc6394ee9",
		}, {
			func() Fields {
				ev := newFields(1,
					"9a3465f82693dd281cb4512a9a650e9be43bf2006be40d636caf84483d5cef40",
					"Hello",
					[]string{"client", "555", ""},
					[]string{"h", "o", "", "2"},
				)
				ev.CreatedAt = 1672519479
				return ev
			},
			15,
			"260",
			"0000b111f860a61feabdd37973f7ce008f5e5e5be041f7828d3774bdbf8fa8c4",
		},
	}

	for _, test := range tests {
		t.Run("test", func(t *testing.T) {
			ev := test.fields()
			id, nonceTag, err := Mine(context.Background(), ev, test.difficulty)
			if err != nil {
				t.Fatal(err)
			}
			if nonceTag[1] != test.nonce {
				t.Fatalf("unexpected nonce got=%s want=%s", nonceTag[1], test.nonce)
			}

			if id != test.eventID {
				t.Fatalf("mismatched event ID: expected %s, got %s", test.eventID, id)
			}
		})
	}

}

// TestValidationThreshold checks that PoW validation accepts greater-than-or-equal difficulty.
func TestValidationThreshold(t *testing.T) {
	// Strategy: We want to prove that ValidatePow accepts an event where
	// actual_zeros > target_difficulty.
	// Instead of tampering with tags (which breaks the ID hash), we effectively
	// mine for a low difficulty (e.g. 1) repeatedly until we get "lucky"
	// and find a hash with >1 zeros.

	targetDiff := 1
	foundLucky := false

	// Try up to 50 times to find a lucky hash.
	// Prob of getting >1 zero when targeting 1 is high (50% per bit).
	for i := range 50 {
		ev := newFields(1, publicKey, "mining for luck")
		// Make content unique to get different hashes
		ev.Content = hex.EncodeToString([]byte{byte(i)})

		id, nonceTag, err := Mine(context.Background(), ev, targetDiff)
		if err != nil {
			t.Fatalf("mining failed: %v", err)
		}

		zeros, err := countZerosFromHex(id)
		if err != nil {
			t.Fatal(err)
		}

		if zeros > targetDiff {
			t.Logf("Found lucky hash! Target=%d, Actual=%d, ID=%s", targetDiff, zeros, id)

			ev.ID = id
			ev.Tags = append(ev.Tags, nonceTag)

			// Verify ValidatePow accepts it
			_, diff, err := ValidatePow(ev)
			if err != nil {
				t.Fatalf("ValidatePow rejected lucky hash (zeros=%d >= diff=%d): %v", zeros, targetDiff, err)
			}
			if diff != targetDiff {
				t.Fatalf("Parsed difficulty mismatch: got %d want %d", diff, targetDiff)
			}
			foundLucky = true
			break
		}
	}

	if !foundLucky {
		t.Skip("Could not find a lucky hash with zeros > target in 50 tries. Skipping threshold test.")
	}
}

// TestNip13MineParallel proves WithWorkers(n>1) still produces a nonce that
// ValidatePow accepts. It doesn't assert an exact nonce/ID like TestNip13Mine
// does -- with multiple workers racing over different nonce strides, which
// one wins (and thus the resulting nonce/ID) is no longer deterministic.
func TestNip13MineParallel(t *testing.T) {
	ev := newFields(1, publicKey, "parallel mining test")
	difficulty := 12

	id, nonceTag, err := Mine(context.Background(), ev, difficulty, WithWorkers(4))
	if err != nil {
		t.Fatalf("mining failed: %v", err)
	}

	ev.ID = id
	ev.Tags = append(ev.Tags, nonceTag)

	if _, diff, err := ValidatePow(ev); err != nil {
		t.Fatalf("ValidatePow rejected a parallel-mined event: %v", err)
	} else if diff != difficulty {
		t.Fatalf("difficulty mismatch: want %d got %d", difficulty, diff)
	}
}

// TestNip13MineCancellationNoLeak proves a cancelled parallel Mine call
// returns promptly (rather than hanging on a worker or the progress ticker)
// and doesn't leak any of its goroutines.
func TestNip13MineCancellationNoLeak(t *testing.T) {
	ev := newFields(1, publicKey, "cancellation test")
	// High enough that mining has no realistic chance of finishing on its
	// own before the test cancels it.
	const difficulty = 40

	before := runtime.NumGoroutine()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, _, err := Mine(ctx, ev, difficulty, WithWorkers(4), WithProgress(time.Millisecond, func(Progress) {}))
		done <- err
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err == nil {
			t.Error("expected an error from a cancelled Mine call, got nil")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Mine did not return promptly after cancellation")
	}

	// Give any still-unwinding goroutines a moment to actually exit before
	// sampling the count.
	time.Sleep(100 * time.Millisecond)
	if after := runtime.NumGoroutine(); after > before+2 {
		t.Errorf("possible goroutine leak: before=%d after=%d", before, after)
	}
}

// TestNip13MineProgress proves progress callbacks report monotonically
// increasing hash counts. It intentionally doesn't fail if zero samples
// fired (mining can finish faster than the tick interval on a fast
// machine) -- there's nothing to assert in that case, so it skips instead.
func TestNip13MineProgress(t *testing.T) {
	ev := newFields(1, publicKey, "progress test")
	const difficulty = 18

	var mu sync.Mutex
	var samples []Progress

	_, _, err := Mine(context.Background(), ev, difficulty, WithWorkers(2), WithProgress(200*time.Microsecond, func(p Progress) {
		mu.Lock()
		defer mu.Unlock()
		samples = append(samples, p)
	}))
	if err != nil {
		t.Fatalf("mining failed: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(samples) == 0 {
		t.Skip("mining finished before any progress tick fired -- nothing to assert")
	}
	for i := 1; i < len(samples); i++ {
		if samples[i].HashesTried < samples[i-1].HashesTried {
			t.Errorf("HashesTried decreased: sample %d=%d, sample %d=%d", i-1, samples[i-1].HashesTried, i, samples[i].HashesTried)
		}
		if samples[i].Workers != 2 {
			t.Errorf("sample %d: expected Workers=2, got %d", i, samples[i].Workers)
		}
	}
}
