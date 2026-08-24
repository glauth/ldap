// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ldap

import (
	"errors"
	"strings"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

func ServerApplyFilter(f *ber.Packet, entry *ldap.Entry) (bool, uint16) {
	switch ldap.FilterMap[uint64(f.Tag)] {
	default:
		//log.Fatalf("Unknown LDAP filter code: %d", f.Tag)
		return false, ldap.LDAPResultOperationsError
	case "Equality Match":
		if len(f.Children) != 2 {
			return false, ldap.LDAPResultOperationsError
		}
		attribute := f.Children[0].Value.(string)
		value := f.Children[1].Value.(string)
		if strings.ToLower(attribute) == "dn" {
			if strings.EqualFold(entry.DN, value) {
				return true, ldap.LDAPResultSuccess
			}
		}
		for _, a := range entry.Attributes {
			if strings.EqualFold(a.Name, attribute) {
				for _, v := range a.Values {
					if strings.EqualFold(v, value) {
						return true, ldap.LDAPResultSuccess
					}
				}
			}
		}
	case "Present":
		for _, a := range entry.Attributes {
			if strings.EqualFold(a.Name, f.Data.String()) {
				return true, ldap.LDAPResultSuccess
			}
		}
	case "And":
		for _, child := range f.Children {
			ok, exitCode := ServerApplyFilter(child, entry)
			if exitCode != ldap.LDAPResultSuccess {
				return false, exitCode
			}
			if !ok {
				return false, ldap.LDAPResultSuccess
			}
		}
		return true, ldap.LDAPResultSuccess
	case "Or":
		anyOk := false
		for _, child := range f.Children {
			ok, exitCode := ServerApplyFilter(child, entry)
			if exitCode != ldap.LDAPResultSuccess {
				return false, exitCode
			} else if ok {
				anyOk = true
			}
		}
		if anyOk {
			return true, ldap.LDAPResultSuccess
		}
	case "Not":
		if len(f.Children) != 1 {
			return false, ldap.LDAPResultOperationsError
		}
		ok, exitCode := ServerApplyFilter(f.Children[0], entry)
		if exitCode != ldap.LDAPResultSuccess {
			return false, exitCode
		} else if !ok {
			return true, ldap.LDAPResultSuccess
		}
	case "Substrings":
		if len(f.Children) != 2 {
			return false, ldap.LDAPResultOperationsError
		}
		attribute := f.Children[0].Value.(string)
		valueBytes := f.Children[1].Children[0].Data.Bytes()
		valueLower := strings.ToLower(string(valueBytes[:]))
		for _, a := range entry.Attributes {
			if strings.EqualFold(a.Name, attribute) {
				for _, v := range a.Values {
					vLower := strings.ToLower(v)
					switch f.Children[1].Children[0].Tag {
					case ldap.FilterSubstringsInitial:
						if strings.HasPrefix(vLower, valueLower) {
							return true, ldap.LDAPResultSuccess
						}
					case ldap.FilterSubstringsAny:
						if strings.Contains(vLower, valueLower) {
							return true, ldap.LDAPResultSuccess
						}
					case ldap.FilterSubstringsFinal:
						if strings.HasSuffix(vLower, valueLower) {
							return true, ldap.LDAPResultSuccess
						}
					}
				}
			}
		}
	case "Greater Or Equal": // TODO
		return false, ldap.LDAPResultOperationsError
	case "Less Or Equal": // TODO
		return false, ldap.LDAPResultOperationsError
	case "Approx Match": // TODO
		return false, ldap.LDAPResultOperationsError
	case "Extensible Match":
		// We don't implement extensible matching server-side; defer to backend results.
		return true, ldap.LDAPResultSuccess
	}

	return false, ldap.LDAPResultSuccess
}

func GetFilterObjectClass(filter string) (string, error) {
	f, err := ldap.CompileFilter(filter)
	if err != nil {
		return "", err
	}
	return parseFilterObjectClass(f)
}
func parseFilterObjectClass(f *ber.Packet) (string, error) {
	objectClass := ""
	switch ldap.FilterMap[uint64(f.Tag)] {
	case "Equality Match":
		if len(f.Children) != 2 {
			return "", errors.New("equality match must have only two children")
		}
		attribute := strings.ToLower(f.Children[0].Value.(string))
		value := f.Children[1].Value.(string)
		if attribute == "objectclass" {
			objectClass = strings.ToLower(value)
		}
	case "And":
		for _, child := range f.Children {
			subType, err := parseFilterObjectClass(child)
			if err != nil {
				return "", err
			}
			if len(subType) > 0 {
				objectClass = subType
			}
		}
	case "Or":
		for _, child := range f.Children {
			subType, err := parseFilterObjectClass(child)
			if err != nil {
				return "", err
			}
			if len(subType) > 0 {
				objectClass = subType
			}
		}
	case "Not":
		if len(f.Children) != 1 {
			return "", errors.New("not filter must have only one child")
		}
		subType, err := parseFilterObjectClass(f.Children[0])
		if err != nil {
			return "", err
		}
		if len(subType) > 0 {
			objectClass = subType
		}

	}
	return strings.ToLower(objectClass), nil
}
