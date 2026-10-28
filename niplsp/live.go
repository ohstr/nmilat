package niplsp

import (
	"fmt"
	"strconv"
)

// Live are the node's live LSPS answers, asked during the live check (NIP-LSP
// §Client Behavior): LSPS0 list_protocols, and LSPS1 or LSPS2 get_info for the
// service about to be used. Read them with ParseListProtocols, ParseLSPS1Info
// and ParseLSPS2Menu. A nil field was not asked and is not compared; an empty
// non-nil one was asked and holds nothing.
type Live struct {
	Protocols []int
	LSPS1     []Option
	LSPS2Menu []FeeRow
}

// Verdict is how a live value compares with the announced one, for the buyer.
type Verdict int

const (
	// Same is a live value equal to the announced one.
	Same Verdict = iota
	// Worse is a live value worse for the buyer than the announced one, or an
	// announced value the live answer lacks.
	Worse
	// Better is a live value better for the buyer, or a live fee row beyond
	// the announced ones.
	Better
)

func (v Verdict) String() string {
	switch v {
	case Same:
		return "same"
	case Worse:
		return "worse"
	case Better:
		return "better"
	}
	return "Verdict(" + strconv.Itoa(int(v)) + ")"
}

// FieldDiff is one compared value. Field is the lsps1 option's name, or
// "lsps2_fee[i].<field>" for row i of the menu (min_fee, proportional,
// min_lifetime, max_client_to_self_delay, min_payment_size,
// max_payment_size). An empty Announced or Live means that side has no value.
type FieldDiff struct {
	Field     string
	Announced string
	Live      string
	Verdict   Verdict
}

// LiveDiff is CheckLive's result.
type LiveDiff struct {
	// MissingProtocol are announced protocols list_protocols does not list:
	// the client does not use the LSP.
	MissingProtocol []int
	// Fields are the compared values, in announcement order.
	Fields []FieldDiff

	asked bool // list_protocols was answered (Live.Protocols non-nil)
}

// Usable reports that list_protocols was asked and lists every announced
// protocol.
func (d LiveDiff) Usable() bool { return d.asked && len(d.MissingProtocol) == 0 }

// Worse reports any live value worse for the buyer than announced. The client
// SHOULD show both and ask again before buying.
func (d LiveDiff) Worse() bool { return d.count(Worse) > 0 }

// Same reports every protocol listed and every compared value equal.
func (d LiveDiff) Same() bool { return d.Usable() && d.count(Same) == len(d.Fields) }

// Changed are the values that differ, worse or better.
func (d LiveDiff) Changed() []FieldDiff {
	var out []FieldDiff
	for _, f := range d.Fields {
		if f.Verdict != Same {
			out = append(out, f)
		}
	}
	return out
}

func (d LiveDiff) count(v Verdict) int {
	n := 0
	for _, f := range d.Fields {
		if f.Verdict == v {
			n++
		}
	}
	return n
}

// CheckLive compares an announcement with the node's live answers; the live
// answers decide (NIP-LSP §Client Behavior, Live check). Each announced
// protocol missing from l.Protocols is in MissingProtocol. Each known lsps1
// option is compared with its live value, and each lsps2_fee row with the live
// menu's row at the same position, field by field, as worse, same or better
// for the buyer: a higher minimum, fee, proportional fee or required
// confirmation count is worse; a lower maximum, lifetime or expiry is worse;
// losing zero-reserve support is worse. LSPS5 fields have no live counterpart
// in the check and are not compared.
func CheckLive(a *Announcement, l Live) LiveDiff {
	var d LiveDiff
	if a == nil {
		return d
	}
	if l.Protocols != nil {
		d.asked = true
		listed := map[int]bool{}
		for _, p := range l.Protocols {
			listed[p] = true
		}
		for _, p := range a.Protocols {
			if !listed[p] {
				d.MissingProtocol = append(d.MissingProtocol, p)
			}
		}
	}
	if l.LSPS1 != nil {
		for _, o := range a.LSPS1 {
			k, known := lookupOption(lsps1Options, o.Name)
			if !known {
				continue
			}
			live, _ := optionValue(l.LSPS1, o.Name)
			d.Fields = append(d.Fields, FieldDiff{
				Field: o.Name, Announced: o.Value, Live: live, Verdict: compare(k.Better, o.Value, live),
			})
		}
	}
	if l.LSPS2Menu != nil {
		n := max(len(a.LSPS2), len(l.LSPS2Menu))
		for i := 0; i < n; i++ {
			var ann, live [6]uint64
			hasAnn, hasLive := i < len(a.LSPS2), i < len(l.LSPS2Menu)
			if hasAnn {
				ann = a.LSPS2[i].values()
			}
			if hasLive {
				live = l.LSPS2Menu[i].values()
			}
			for j, k := range feeRowFields {
				fd := FieldDiff{Field: fmt.Sprintf("lsps2_fee[%d].%s", i, k.Name)}
				if hasAnn {
					fd.Announced = strconv.FormatUint(ann[j], 10)
				}
				if hasLive {
					fd.Live = strconv.FormatUint(live[j], 10)
				}
				switch {
				case !hasLive:
					fd.Verdict = Worse
				case !hasAnn:
					fd.Verdict = Better
				default:
					fd.Verdict = compare(k.Better, fd.Announced, fd.Live)
				}
				d.Fields = append(d.Fields, fd)
			}
		}
	}
	return d
}

// compare judges live against announced in direction dir. A missing or
// unreadable live value is worse.
func compare(dir direction, announced, live string) Verdict {
	if announced == live {
		return Same
	}
	if dir == trueBetter {
		switch {
		case live == "true" && announced == "false":
			return Better
		default:
			return Worse
		}
	}
	av, okA := canonicalUint(announced)
	lv, okL := canonicalUint(live)
	switch {
	case !okL:
		return Worse
	case !okA:
		return Better
	case lv == av:
		return Same
	case (lv < av) == (dir == lowerBetter):
		return Better
	}
	return Worse
}
