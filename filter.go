// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ldaps

import (
	"errors"
	"fmt"
	"strings"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

var ErrInvalidFilter = errors.New("invalid filter")

func ApplyFilter(f *ber.Packet, entry *ldap.Entry) (bool, *ldap.Error) {
	// Note: ldap.LDAPResultProtocolError is used for invalid queries. eg equals only having one attribute
	// ldap.LDAPResultFilterError is used for not implemented or attributes that don't exist
	// see https://datatracker.ietf.org/doc/html/rfc4511#section-4.5.1.7
	// and Clause 7.8 of https://www.itu.int/rec/T-REC-X.511-201910-I/en for more information
	// TODO: change return value to an enum to handle "UNDEFINED" properly
	switch f.Tag {
	default:
		return false, &ldap.Error{ResultCode: ldap.LDAPResultFilterError, Err: fmt.Errorf("unknown LDAP filter code: %d", f.Tag)}

	case ldap.FilterEqualityMatch:
		if len(f.Children) != 2 {
			return false, &ldap.Error{ResultCode: ldap.LDAPResultProtocolError, Err: fmt.Errorf("%w: %w", ErrInvalidFilter, ErrInvalidPacketLength)}
		}

		attribute, ok := f.Children[0].Value.(string)
		if !ok {
			return false, &ldap.Error{ResultCode: ldap.LDAPResultProtocolError, Err: ErrInvalidFilter}
		}

		value, ok := f.Children[1].Value.(string)
		if !ok {
			return false, &ldap.Error{ResultCode: ldap.LDAPResultProtocolError, Err: ErrInvalidFilter}
		}

		if strings.EqualFold(attribute, "dn") && strings.EqualFold(entry.DN, value) {
			return true, nil
		}
		for _, a := range entry.Attributes {
			if strings.EqualFold(a.Name, attribute) {
				for _, v := range a.Values {
					if strings.EqualFold(v, value) {
						return true, nil
					}
				}
			}
		}

	case ldap.FilterPresent:
		for _, a := range entry.Attributes {
			if strings.EqualFold(a.Name, f.Data.String()) {
				return true, nil
			}
		}

	case ldap.FilterAnd:
		for _, child := range f.Children {
			ok, err := ApplyFilter(child, entry)
			if err != nil || !ok {
				return false, err
			}
		}

		return true, nil

	case ldap.FilterOr:
		for _, child := range f.Children {
			ok, err := ApplyFilter(child, entry)
			if err != nil || ok {
				return ok, err
			}
		}

	case ldap.FilterNot:
		if len(f.Children) != 1 {
			return false, &ldap.Error{ResultCode: ldap.LDAPResultProtocolError, Err: fmt.Errorf("%w: %w", ErrInvalidFilter, ErrInvalidPacketLength)}
		}
		ok, err := ApplyFilter(f.Children[0], entry)
		if err != nil {
			return false, err
		}
		return !ok, nil

	case ldap.FilterSubstrings:
		if len(f.Children) != 2 {
			return false, &ldap.Error{ResultCode: ldap.LDAPResultProtocolError, Err: fmt.Errorf("%w: %w", ErrInvalidFilter, ErrInvalidPacketLength)}
		}
		attribute, ok := f.Children[0].Value.(string)
		if !ok {
			return false, &ldap.Error{ResultCode: ldap.LDAPResultProtocolError, Err: ErrInvalidFilter}
		}
		var attr *ldap.EntryAttribute
		for _, a := range entry.Attributes {
			if strings.EqualFold(a.Name, attribute) {
				attr = a

				break
			}
		}
		if attr == nil {
			break
		}

	valueLoop:
		for _, v := range attr.Values { // Check each value to see if it matches. Used for memberOf searches
			value := strings.ToLower(v)
			matched := false

			for _, s := range f.Children[1].Children { // Check each part of the filter ('beg' and 'end' in 'beg*end'). This can't end early because if we are checking group membership the group may not be the first listed group
				search := strings.ToLower(s.Data.String())

				switch s.Tag {
				case ldap.FilterSubstringsInitial:
					value, matched = strings.CutPrefix(value, search)
				case ldap.FilterSubstringsAny:
					matched = strings.Contains(value, search)
				case ldap.FilterSubstringsFinal:
					value, matched = strings.CutSuffix(value, search)
				default:
					continue valueLoop
				}
			}

			if matched {
				return true, nil
			}
		}

	case ldap.FilterGreaterOrEqual: // TODO
		return false, &ldap.Error{ResultCode: ldap.LDAPResultFilterError, Err: fmt.Errorf("filter %s not implemented", ldap.FilterMap[uint64(f.Tag)])}

	case ldap.FilterLessOrEqual: // TODO
		return false, &ldap.Error{ResultCode: ldap.LDAPResultFilterError, Err: fmt.Errorf("filter %s not implemented", ldap.FilterMap[uint64(f.Tag)])}

	case ldap.FilterApproxMatch: // TODO
		return false, &ldap.Error{ResultCode: ldap.LDAPResultFilterError, Err: fmt.Errorf("filter %s not implemented", ldap.FilterMap[uint64(f.Tag)])}

	case ldap.FilterExtensibleMatch:
		// We don't implement extensible matching server-side; defer to backend results.
		return false, &ldap.Error{ResultCode: ldap.LDAPResultFilterError, Err: fmt.Errorf("filter %s not implemented", ldap.FilterMap[uint64(f.Tag)])}
	}

	return false, nil
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
			return "", ldap.NewError(ldap.LDAPResultProtocolError, fmt.Errorf("%w: %w", ErrInvalidFilter, ErrInvalidPacketLength))
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
			return "", ldap.NewError(ldap.LDAPResultProtocolError, fmt.Errorf("%w: %w", ErrInvalidFilter, ErrInvalidPacketLength))
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
