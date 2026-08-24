package ldap

import (
	"bytes"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

// redecode serializes a packet and parses it again. DecodeControl runs on
// controls parsed from the wire, not on in-memory packets, and the original
// unchecked type assertions / child indexing only panic on wire-decoded
// input. Round-tripping through bytes reproduces that path faithfully.
func redecode(p *ber.Packet) *ber.Packet {
	if p == nil {
		return nil
	}
	return ber.DecodePacket(p.Bytes())
}

func controlSeq(children ...*ber.Packet) *ber.Packet {
	seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	for _, c := range children {
		seq.AppendChild(c)
	}
	return seq
}

func octet(s string) *ber.Packet {
	return ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, s, "")
}

// pagingControl builds a paging control whose value wraps the supplied inner
// sequence, mirroring ControlPaging.Encode() so the byte layout matches the
// real wire format.
func pagingControl(inner *ber.Packet) *ber.Packet {
	ctrl := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	ctrl.AppendChild(octet(ldap.ControlTypePaging))
	value := ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, nil, "Control Value (Paging)")
	value.AppendChild(inner)
	ctrl.AppendChild(value)
	return ctrl
}

func searchValueSeq(children ...*ber.Packet) *ber.Packet {
	seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Search Control Value")
	for _, c := range children {
		seq.AppendChild(c)
	}
	return seq
}

func integer(v uint64) *ber.Packet {
	return ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, v, "")
}

func TestDecodeControl(t *testing.T) {
	tests := []struct {
		name    string
		packet  *ber.Packet
		wantErr bool
		check   func(t *testing.T, c ldap.Control)
	}{
		{
			name:   "string control, type only",
			packet: redecode((&ldap.ControlString{ControlType: "1.2.3.4"}).Encode()),
			check: func(t *testing.T, c ldap.Control) {
				cs, ok := c.(*ldap.ControlString)
				if !ok {
					t.Fatalf("got %T, want *ControlString", c)
				}
				if cs.ControlType != "1.2.3.4" {
					t.Errorf("ControlType = %q, want 1.2.3.4", cs.ControlType)
				}
				if cs.Criticality {
					t.Errorf("Criticality = true, want false")
				}
				if cs.ControlValue != "" {
					t.Errorf("ControlValue = %q, want empty", cs.ControlValue)
				}
			},
		},
		{
			name:   "string control, type and value",
			packet: redecode((&ldap.ControlString{ControlType: "1.2.3.4", ControlValue: "payload"}).Encode()),
			check: func(t *testing.T, c ldap.Control) {
				cs := c.(*ldap.ControlString)
				if cs.Criticality {
					t.Errorf("Criticality = true, want false")
				}
				if cs.ControlValue != "payload" {
					t.Errorf("ControlValue = %q, want payload", cs.ControlValue)
				}
			},
		},
		{
			name:   "string control, type criticality and value",
			packet: redecode((&ldap.ControlString{ControlType: "1.2.3.4", Criticality: true, ControlValue: "payload"}).Encode()),
			check: func(t *testing.T, c ldap.Control) {
				cs := c.(*ldap.ControlString)
				if !cs.Criticality {
					t.Errorf("Criticality = false, want true")
				}
				if cs.ControlValue != "payload" {
					t.Errorf("ControlValue = %q, want payload", cs.ControlValue)
				}
			},
		},
		{
			name:   "paging control round-trip",
			packet: redecode((&ldap.ControlPaging{PagingSize: 100, Cookie: []byte("cookie")}).Encode()),
			check: func(t *testing.T, c ldap.Control) {
				cp, ok := c.(*ldap.ControlPaging)
				if !ok {
					t.Fatalf("got %T, want *ControlPaging", c)
				}
				if cp.PagingSize != 100 {
					t.Errorf("PagingSize = %d, want 100", cp.PagingSize)
				}
				if !bytes.Equal(cp.Cookie, []byte("cookie")) {
					t.Errorf("Cookie = %q, want cookie", cp.Cookie)
				}
			},
		},
		// {
		// 	name:    "nil packet",
		// 	packet:  nil,
		// 	wantErr: true,
		// },
		{
			name:    "empty control sequence",
			packet:  redecode(controlSeq()),
			wantErr: true,
		},
		{
			name:    "control type not an octet string",
			packet:  redecode(controlSeq(integer(5))),
			wantErr: true,
		},
		{
			name: "criticality not a boolean",
			packet: redecode(controlSeq(
				octet("1.2.3.4"),
				octet("not-a-bool"),
				octet("value"),
			)),
			wantErr: true,
		},
		{
			name:    "paging value sequence too short",
			packet:  redecode(pagingControl(searchValueSeq(integer(10)))),
			wantErr: true,
		},
		// {
		// 	name:    "paging size exceeds uint32",
		// 	packet:  redecode(pagingControl(searchValueSeq(integer(uint64(1)<<32), octet("ck")))),
		// 	wantErr: true,
		// },
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := ldap.DecodeControl(tt.packet)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("DecodeControl() error = nil, want error")
				}
				if c != nil {
					t.Errorf("DecodeControl() control = %v, want nil on error", c)
				}
				return
			}
			if err != nil {
				t.Fatalf("DecodeControl() unexpected error: %v", err)
			}
			if c == nil {
				t.Fatalf("DecodeControl() control = nil, want non-nil")
			}
			if tt.check != nil {
				tt.check(t, c)
			}
		})
	}
}
