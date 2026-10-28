package nipCP

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// DeviceStore is one device-local store holding the device id and the record of
// derived ids this device placed (NIP-CP §Kind 9525 `device`, §Writing, The
// local record). Both live and are lost together, and neither is copied by
// backup or restore: a wallet that finds it runs from copied or restored state
// SHOULD start a new store (NewDeviceID), and then treats the old id's open
// entries as another device's.
type DeviceStore interface {
	// DeviceID is this device's id, lowercase hex.
	DeviceID(ctx context.Context) (string, error)
	// RecordDerived notes a derived id placed here, kept until keepUntil.
	RecordDerived(ctx context.Context, id string, keepUntil int64) error
	// DerivedPlaced reports a derived id already placed here.
	DerivedPlaced(ctx context.Context, id string) (bool, error)
}

// NewDeviceID is a fresh device id: 16 random bytes as lowercase hex.
func NewDeviceID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("nipCP: device id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}
