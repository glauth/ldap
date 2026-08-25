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
	{filterStr: "(sn=M" + ldap.EscapeFilter("ö") + "*ller)", filterType: ldap.FilterSubstrings},
	{filterStr: "(sn=M*" + ldap.EscapeFilter("ö") + "*ller)", filterType: ldap.FilterSubstrings},
	{filterStr: "(sn=*" + ldap.EscapeFilter("ö") + "*ll*)", filterType: ldap.FilterSubstrings},
	// { filterStr: "()", filterType: ldap.FilterExtensibleMatch },
}

func TestFilter(t *testing.T) {
	// Test Compiler and Decompiler
	for _, i := range testFilters {
		filter, err := ldap.CompileFilter(i.filterStr)
		if err != nil {
			t.Errorf("Problem compiling %s - %v", i.filterStr, err)
		} else if filter.Tag != i.filterType {
			t.Errorf("%q Expected %q got %q", i.filterStr, ldap.FilterMap[uint64(i.filterType)], ldap.FilterMap[uint64(filter.Tag)])
		} else {
			o, err := ldap.DecompileFilter(filter)
			if err != nil {
				t.Errorf("Problem compiling %s - %v", i.filterStr, err)
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

func TestGetFilterAttribute(t *testing.T) {
	for _, testInfo := range []struct {
		Filter    string
		Attribute string
		Expected  string
	}{
		{
			Filter:    "(objectClass=*)",
			Attribute: "objectclass",
			Expected:  "",
		},
		{
			Filter:    "(objectClass=posixAccount)",
			Attribute: "objectClass",
			Expected:  "posixAccount",
		},
		{
			Filter:    "(&(cn=awesome)(objectClass=posixGroup))",
			Attribute: "objectClass",
			Expected:  "posixGroup",
		},
		{
			Filter:    "(&(cn=awesome)(objectClass=posixGroup))",
			Attribute: "cn",
			Expected:  "awesome",
		},
	} {
		value, err := GetFilterAttribute(testInfo.Filter, testInfo.Attribute)
		if err != nil {
			t.Errorf("GetFilterAttribute failed: %v", err)
		}
		if value != testInfo.Expected {
			t.Errorf("GetFilterAttribute: Expected %q got %q", testInfo.Expected, value)
		}
	}
}

func TestApplyFilter(t *testing.T) {
	for _, testInfo := range []struct {
		Filter   string
		Entry    *ldap.Entry
		Expected bool
	}{
		{
			Filter:   "(objectClass=*)",
			Entry:    ldap.NewEntry("cn=test,ou=users,dc=example,dc=org", map[string][]string{"objectclass": {"User"}}),
			Expected: true,
		},
		{
			Filter: "(memberOf=cn=*sers,ou=groups,dc=example,dc=org)",
			Entry: ldap.NewEntry(
				"cn=test,ou=users,dc=example,dc=org",
				map[string][]string{
					"objectclass": {"User"},
					"memberOf":    {"cn=users,ou=groups,dc=example,dc=org"},
				}),
			Expected: true,
		},
		{
			Filter: "(memberOf=cn=*sers,ou=groups,dc=example,dc=org)",
			Entry: ldap.NewEntry(
				"cn=test,ou=users,dc=example,dc=org",
				map[string][]string{
					"objectclass": {"User"},
					"memberOf":    {"cn=admins,ou=groups,dc=example,dc=org"},
				}),
			Expected: false,
		},
	} {
		berFilter, err := ldap.CompileFilter(testInfo.Filter)
		if err != nil {
			t.Errorf("Compiling the filter failed: %v", err)
		}
		matched, ldapResult := ServerApplyFilter(berFilter, testInfo.Entry)
		if matched != testInfo.Expected {
			status := "did not match"
			if matched {
				status = "matched"
			}
			t.Errorf("Entry: %v %s: %q return code: %s", testInfo.Entry, status, testInfo.Filter, ldap.LDAPResultCodeMap[ldapResult])
		}
	}
}

// TestServerApplyFilterSubstrings checks that every component of a substring
// assertion is matched, in order and without overlap.
func TestServerApplyFilterSubstrings(t *testing.T) {
	entry := func(cn string) *ldap.Entry {
		return &ldap.Entry{
			DN:         "cn=" + cn + ",ou=users,dc=example,dc=com",
			Attributes: []*ldap.EntryAttribute{{Name: "cn", Values: []string{cn}}},
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
		filter, err := ldap.CompileFilter(tt.filterStr)
		if err != nil {
			t.Errorf("Problem compiling %s - %s", tt.filterStr, err.Error())
			continue
		}
		keep, err := ApplyFilter(filter, entry(tt.cn))
		if StatusCode(err) != ldap.LDAPResultSuccess {
			t.Errorf("%s against %q: unexpected error %v", tt.filterStr, tt.cn, err)
		} else if keep != tt.expected {
			t.Errorf("%s against %q: expected %v, got %v", tt.filterStr, tt.cn, tt.expected, keep)
		}
	}
}
