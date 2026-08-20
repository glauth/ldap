package ldap

import (
	"reflect"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
)

type compileTest struct {
	filterStr  string
	filterType ber.Tag
}

var testFilters = []compileTest{
	{filterStr: "(&(sn=Müller)(givenName=Bob))", filterType: FilterAnd},
	{filterStr: "(|(sn=Möller)(givenName=Bob))", filterType: FilterOr},
	{filterStr: "(!(sn=Møller))", filterType: FilterNot},
	{filterStr: "(sn=Müller)", filterType: FilterEqualityMatch},
	{filterStr: "(sn=Möll*)", filterType: FilterSubstrings},
	{filterStr: "(sn=*Møll)", filterType: FilterSubstrings},
	{filterStr: "(sn=*Müll*)", filterType: FilterSubstrings},
	{filterStr: "(sn=Mö*ller)", filterType: FilterSubstrings},
	{filterStr: "(sn=M*ö*ller)", filterType: FilterSubstrings},
	{filterStr: "(sn=*ö*ll*)", filterType: FilterSubstrings},
	{filterStr: "(sn>=Möller)", filterType: FilterGreaterOrEqual},
	{filterStr: "(sn<=Møller)", filterType: FilterLessOrEqual},
	{filterStr: "(sn=*)", filterType: FilterPresent},
	{filterStr: "(sn~=Müller)", filterType: FilterApproxMatch},
	// { filterStr: "()", filterType: FilterExtensibleMatch },
}

func TestFilter(t *testing.T) {
	// Test Compiler and Decompiler
	for _, i := range testFilters {
		filter, err := CompileFilter(i.filterStr)
		if err != nil {
			t.Errorf("Problem compiling %s - %s", i.filterStr, err.Error())
		} else if filter.Tag != i.filterType {
			t.Errorf("%q Expected %q got %q", i.filterStr, FilterMap[i.filterType], FilterMap[filter.Tag])
		} else {
			o, err := DecompileFilter(filter)
			if err != nil {
				t.Errorf("Problem compiling %s - %s", i.filterStr, err.Error())
			} else if i.filterStr != o {
				t.Errorf("%q expected, got %q", i.filterStr, o)
			}
		}
	}
}

type binTestFilter struct {
	bin []byte
	str string
}

var binTestFilters = []binTestFilter{
	{bin: []byte{0x87, 0x06, 0x6d, 0x65, 0x6d, 0x62, 0x65, 0x72}, str: "(member=*)"},
}

func TestFiltersDecode(t *testing.T) {
	for i, test := range binTestFilters {
		p := ber.DecodePacket(test.bin)
		if filter, err := DecompileFilter(p); err != nil {
			t.Errorf("binTestFilters[%d], DecompileFilter returned : %s", i, err)
		} else if filter != test.str {
			t.Errorf("binTestFilters[%d], %q expected, got %q", i, test.str, filter)
		}
	}
}

func TestFiltersEncode(t *testing.T) {
	for i, test := range binTestFilters {
		p, err := CompileFilter(test.str)
		if err != nil {
			t.Errorf("binTestFilters[%d], CompileFilter returned : %s", i, err)
			continue
		}
		b := p.Bytes()
		if !reflect.DeepEqual(b, test.bin) {
			t.Errorf("binTestFilters[%d], %q expected for CompileFilter(%q), got %q", i, test.bin, test.str, b)
		}
	}
}

func BenchmarkFilterCompile(b *testing.B) {
	b.StopTimer()
	filters := make([]string, len(testFilters))

	// Test Compiler and Decompiler
	for idx, i := range testFilters {
		filters[idx] = i.filterStr
	}

	maxIdx := len(filters)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		CompileFilter(filters[i%maxIdx])
	}
}

func BenchmarkFilterDecompile(b *testing.B) {
	b.StopTimer()
	filters := make([]*ber.Packet, len(testFilters))

	// Test Compiler and Decompiler
	for idx, i := range testFilters {
		filters[idx], _ = CompileFilter(i.filterStr)
	}

	maxIdx := len(filters)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		DecompileFilter(filters[i%maxIdx])
	}
}

func TestGetFilterObjectClass(t *testing.T) {
	c, err := GetFilterObjectClass("(objectClass=*)")
	if err != nil {
		t.Errorf("GetFilterObjectClass failed")
	}
	if c != "" {
		t.Errorf("GetFilterObjectClass failed")
	}
	c, err = GetFilterObjectClass("(objectClass=posixAccount)")
	if err != nil {
		t.Errorf("GetFilterObjectClass failed")
	}
	if c != "posixaccount" {
		t.Errorf("GetFilterObjectClass failed")
	}
	c, err = GetFilterObjectClass("(&(cn=awesome)(objectClass=posixGroup))")
	if err != nil {
		t.Errorf("GetFilterObjectClass failed")
	}
	if c != "posixgroup" {
		t.Errorf("GetFilterObjectClass failed")
	}
}

// TestSubstringFilterWireFormat decompiles SubstringFilter packets built the way
// a client puts them on the wire: one child per component. CompileFilter cannot
// produce this shape for a multi-component pattern, so a compile/decompile round
// trip does not exercise it.
func TestSubstringFilterWireFormat(t *testing.T) {
	type part struct {
		tag   ber.Tag
		value string
	}
	build := func(attribute string, parts []part) *ber.Packet {
		packet := ber.Encode(ber.ClassContext, ber.TypeConstructed, FilterSubstrings, nil, FilterMap[FilterSubstrings])
		packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, attribute, "Attribute"))
		seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Substrings")
		for _, p := range parts {
			seq.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, p.tag, p.value, "Substring"))
		}
		packet.AppendChild(seq)
		return packet
	}

	tests := []struct {
		name     string
		attr     string
		parts    []part
		expected string
	}{
		{"initial", "cn", []part{{FilterSubstringsInitial, "svc-"}}, "(cn=svc-*)"},
		{"any", "cn", []part{{FilterSubstringsAny, "door"}}, "(cn=*door*)"},
		{"final", "mail", []part{{FilterSubstringsFinal, "@example.com"}}, "(mail=*@example.com)"},
		{"initial and final", "cn", []part{{FilterSubstringsInitial, "svc-"}, {FilterSubstringsFinal, "-prod"}}, "(cn=svc-*-prod)"},
		{"initial any final", "cn", []part{{FilterSubstringsInitial, "a"}, {FilterSubstringsAny, "b"}, {FilterSubstringsFinal, "c"}}, "(cn=a*b*c)"},
		{"two any", "cn", []part{{FilterSubstringsAny, "door"}, {FilterSubstringsAny, "prod"}}, "(cn=*door*prod*)"},
	}
	for _, tt := range tests {
		o, err := DecompileFilter(build(tt.attr, tt.parts))
		if err != nil {
			t.Errorf("%s: %s", tt.name, err.Error())
		} else if o != tt.expected {
			t.Errorf("%s: %q expected, got %q", tt.name, tt.expected, o)
		}
	}
}

// TestServerApplyFilterSubstrings checks that every component of a substring
// assertion is matched, in order and without overlap.
func TestServerApplyFilterSubstrings(t *testing.T) {
	entry := func(cn string) *Entry {
		return &Entry{
			DN:         "cn=" + cn + ",ou=users,dc=example,dc=com",
			Attributes: []*EntryAttribute{{Name: "cn", Values: []string{cn}}},
		}
	}
	tests := []struct {
		filterStr string
		cn        string
		expected  bool
	}{
		{"(cn=svc-*-prod)", "svc-door-prod", true},
		{"(cn=svc-*-prod)", "svc-door-dev", false},
		{"(cn=a*b*c)", "axxbyyc", true},
		{"(cn=a*b*c)", "acb", false},
		{"(cn=svc-*)", "svc-door-dev", true},
		{"(cn=*door*)", "svc-door-dev", true},
		{"(cn=*prod)", "svc-door-prod", true},
		{"(cn=*prod)", "svc-door-dev", false},
		// initial and final may not consume the same characters
		{"(cn=prod*prod)", "prod", false},
		{"(cn=prod*prod)", "prod-prod", true},
	}
	for _, tt := range tests {
		filter, err := CompileFilter(tt.filterStr)
		if err != nil {
			t.Errorf("Problem compiling %s - %s", tt.filterStr, err.Error())
			continue
		}
		keep, code := ServerApplyFilter(filter, entry(tt.cn))
		if code != LDAPResultSuccess {
			t.Errorf("%s against %q: unexpected result code %d", tt.filterStr, tt.cn, code)
		} else if keep != tt.expected {
			t.Errorf("%s against %q: expected %v, got %v", tt.filterStr, tt.cn, tt.expected, keep)
		}
	}
}
