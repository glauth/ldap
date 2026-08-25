// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ldaps

import (
	"errors"
	"strings"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

var ErrorInvalidFilter = errors.New("invalid filter")

func ServerApplyFilter(f *ber.Packet, entry *ldap.Entry) (bool, uint16) {
	// Note: ldap.LDAPResultProtocolError is used for invalid queries. eg equals only having one attribute
	// ldap.LDAPResultFilterError is used for not implemented or attributes that don't exist
	// see https://datatracker.ietf.org/doc/html/rfc4511#section-4.5.1.7
	// and Clause 7.8 of https://www.itu.int/rec/T-REC-X.511-201910-I/en for more information
	// TODO: change return value to an enum to handle "UNDEFINED" properly
	switch f.Tag {
	default:
		return false, ldap.LDAPResultFilterError
	case ldap.FilterEqualityMatch:
		if len(f.Children) != 2 {
			return false, ldap.LDAPResultProtocolError
		}
		attribute, ok := f.Children[0].Value.(string)
		if !ok {
			return false, ldap.LDAPResultProtocolError
		}

		value, ok := f.Children[1].Value.(string)
		if !ok {
			return false, ldap.LDAPResultProtocolError
		}

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

	case ldap.FilterPresent:
		for _, a := range entry.Attributes {
			if strings.EqualFold(a.Name, f.Data.String()) {
				return true, ldap.LDAPResultSuccess
			}
		}

	case ldap.FilterAnd:
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
	case ldap.FilterOr:
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
	case ldap.FilterNot:
		if len(f.Children) != 1 {
			return false, ldap.LDAPResultProtocolError
		}
		ok, exitCode := ServerApplyFilter(f.Children[0], entry)
		if exitCode != ldap.LDAPResultSuccess {
			return false, exitCode
		} else if !ok {
			return true, ldap.LDAPResultSuccess
		}

	case ldap.FilterSubstrings:
		if len(f.Children) != 2 {
			return false, ldap.LDAPResultProtocolError
		}
		attribute, ok := f.Children[0].Value.(string)
		if !ok {
			return false, ldap.LDAPResultProtocolError
		}
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
	case ldap.FilterGreaterOrEqual: // TODO
		return false, ldap.LDAPResultFilterError
	case ldap.FilterLessOrEqual: // TODO
		return false, ldap.LDAPResultFilterError
	case ldap.FilterApproxMatch: // TODO
		return false, ldap.LDAPResultFilterError
	case ldap.FilterExtensibleMatch:
		// We don't implement extensible matching server-side; defer to backend results.
		return true, ldap.LDAPResultSuccess
	}

	return false, ldap.LDAPResultSuccess
}

func GetFilterAttribute(filter string, attr string) (string, error) {
	f, err := ldap.CompileFilter(filter)
	if err != nil {
		return "", err
	}
	return parseFilterAttribute(f, attr)
}
func parseFilterAttribute(f *ber.Packet, attr string) (string, error) {
	objectClass := ""
	switch f.Tag {
	case ldap.FilterEqualityMatch:
		if len(f.Children) != 2 {
			return "", ldap.NewError(ldap.LDAPResultProtocolError, errors.New("equality match must have only two children"))
		}
		var (
			attribute string
			value     string
			ok        bool
		)

		attribute, ok = f.Children[0].Value.(string)
		if !ok {
			return "", ldap.NewError(ldap.LDAPResultProtocolError, errors.New("equality match must be a string"))
		}
		value, ok = f.Children[1].Value.(string)
		if !ok {
			return "", ldap.NewError(ldap.LDAPResultProtocolError, errors.New("equality match must be a string"))
		}
		if strings.EqualFold(attribute, attr) {
			objectClass = value
		}
	case ldap.FilterAnd:
		for _, child := range f.Children {
			subType, err := parseFilterAttribute(child, attr)
			if err != nil {
				return "", err
			}
			if len(subType) > 0 {
				objectClass = subType
			}
		}
	case ldap.FilterOr:
		for _, child := range f.Children {
			subType, err := parseFilterAttribute(child, attr)
			if err != nil {
				return "", err
			}
			if len(subType) > 0 {
				objectClass = subType
			}
		}
	case ldap.FilterNot:
		if len(f.Children) != 1 {
			return "", ldap.NewError(ldap.LDAPResultProtocolError, errors.New("not filter must have only one child"))
		}
		subType, err := parseFilterAttribute(f.Children[0], attr)
		if err != nil {
			return "", err
		}
		if len(subType) > 0 {
			objectClass = subType
		}

	}
	return objectClass, nil
}
