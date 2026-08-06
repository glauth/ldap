package ldaps

import (
	"reflect"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

type compileTest struct {
	filterStr  string
	filterType ber.Tag
}

// Uses ldap.EscapeFilter to conform to RFC4515
var testFilters = []compileTest{
	{filterStr: "(&(sn=" + ldap.EscapeFilter("Müller") + ")(givenName=Bob))", filterType: ldap.FilterAnd},
	{filterStr: "(|(sn=" + ldap.EscapeFilter("Möller") + ")(givenName=Bob))", filterType: ldap.FilterOr},
	{filterStr: "(!(sn=" + ldap.EscapeFilter("Møller") + "))", filterType: ldap.FilterNot},
	{filterStr: "(sn=" + ldap.EscapeFilter("Müller") + ")", filterType: ldap.FilterEqualityMatch},
	{filterStr: "(sn=" + ldap.EscapeFilter("Möll") + "*)", filterType: ldap.FilterSubstrings},
	{filterStr: "(sn=*" + ldap.EscapeFilter("Møll") + ")", filterType: ldap.FilterSubstrings},
	{filterStr: "(sn=*" + ldap.EscapeFilter("Müll") + "*)", filterType: ldap.FilterSubstrings},
	{filterStr: "(sn>=" + ldap.EscapeFilter("Möller") + ")", filterType: ldap.FilterGreaterOrEqual},
	{filterStr: "(sn<=" + ldap.EscapeFilter("Møller") + ")", filterType: ldap.FilterLessOrEqual},
	{filterStr: "(sn=*)", filterType: ldap.FilterPresent},
	{filterStr: "(sn~=" + ldap.EscapeFilter("Müller") + ")", filterType: ldap.FilterApproxMatch},
	// { filterStr: "()", filterType: ldap.FilterExtensibleMatch },
}

func TestFilter(t *testing.T) {
	// Test Compiler and Decompiler
	for _, i := range testFilters {
		filter, err := ldap.CompileFilter(i.filterStr)
		if err != nil {
			t.Errorf("Problem compiling %s - %s", i.filterStr, err.Error())
		} else if filter.Tag != i.filterType {
			t.Errorf("%q Expected %q got %q", i.filterStr, ldap.FilterMap[uint64(i.filterType)], ldap.FilterMap[uint64(filter.Tag)])
		} else {
			o, err := ldap.DecompileFilter(filter)
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
		if filter, err := ldap.DecompileFilter(p); err != nil {
			t.Errorf("binTestFilters[%d], DecompileFilter returned : %s", i, err)
		} else if filter != test.str {
			t.Errorf("binTestFilters[%d], %q expected, got %q", i, test.str, filter)
		}
	}
}

func TestFiltersEncode(t *testing.T) {
	for i, test := range binTestFilters {
		p, err := ldap.CompileFilter(test.str)
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
		ldap.CompileFilter(filters[i%maxIdx])
	}
}

func BenchmarkFilterDecompile(b *testing.B) {
	b.StopTimer()
	filters := make([]*ber.Packet, len(testFilters))

	// Test Compiler and Decompiler
	for idx, i := range testFilters {
		filters[idx], _ = ldap.CompileFilter(i.filterStr)
	}

	maxIdx := len(filters)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		ldap.DecompileFilter(filters[i%maxIdx])
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
