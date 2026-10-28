package niplsp

import "strings"

// Unit is the unit an LSPS field name's suffix carries.
type Unit int

const (
	// UnitNone is a field with no unit suffix: a count, blocks, parts per
	// million or a boolean.
	UnitNone Unit = iota
	// UnitBase is an amount in the chain's smallest unit: LSPS's _sat, or
	// _loki in the loki dialect.
	UnitBase
	// UnitMillis is an amount in thousandths of the smallest unit: LSPS's
	// _msat, or _mloki in the loki dialect.
	UnitMillis
)

// Dialect is how an LSPS implementation spells its unit suffixes.
type Dialect int

const (
	// DialectSat is LSPS as written: _sat and _msat.
	DialectSat Dialect = iota
	// DialectLoki is the dialect of LSPS servers on a chain whose smallest
	// unit is the loki: _loki and _mloki.
	DialectLoki
)

// suffixes are the unit suffixes, millis first so that _msat is never read as
// _sat of a name ending in m.
var suffixes = []struct {
	s string
	u Unit
	d Dialect
}{
	{"_msat", UnitMillis, DialectSat},
	{"_mloki", UnitMillis, DialectLoki},
	{"_sat", UnitBase, DialectSat},
	{"_loki", UnitBase, DialectLoki},
}

// FromLSPSName maps an LSPS field name in either dialect to the name an
// announcement uses (without its unit suffix) and the unit of its value:
// "max_channel_balance_sat" and "max_channel_balance_loki" both give
// ("max_channel_balance", UnitBase); "min_fee_msat" and "min_fee_mloki" give
// ("min_fee", UnitMillis); a name without a suffix comes back unchanged with
// UnitNone. Base units and millis are the same numbers in both dialects.
func FromLSPSName(lspsName string) (name string, unit Unit) {
	for _, x := range suffixes {
		if strings.HasSuffix(lspsName, x.s) && len(lspsName) > len(x.s) {
			return strings.TrimSuffix(lspsName, x.s), x.u
		}
	}
	return lspsName, UnitNone
}

// ToLSPSName is the LSPS field name of an announced name with unit u, in
// dialect d: ToLSPSName("min_fee", UnitMillis, DialectLoki) is
// "min_fee_mloki".
func ToLSPSName(name string, u Unit, d Dialect) string {
	for _, x := range suffixes {
		if x.u == u && x.d == d {
			return name + x.s
		}
	}
	return name
}
