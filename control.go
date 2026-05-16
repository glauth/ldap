// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ldap

import (
	"fmt"
	"strings"

	ber "github.com/go-asn1-ber/asn1-ber"
)

const (
	ControlTypePaging = "1.2.840.113556.1.4.319"
)

var ControlTypeMap = map[string]string{
	ControlTypePaging: "Paging",
}

type Control interface {
	GetControlType() string
	Encode() *ber.Packet
	String() string
}

type ControlString struct {
	ControlType  string
	Criticality  bool
	ControlValue string
}

func (c *ControlString) GetControlType() string {
	return c.ControlType
}

func (c *ControlString) Encode() *ber.Packet {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, c.ControlType, "Control Type ("+ControlTypeMap[c.ControlType]+")"))
	if c.Criticality {
		packet.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, c.Criticality, "Criticality"))
	}
	if strings.TrimSpace(c.ControlValue) != "" {
		packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, c.ControlValue, "Control Value"))
	}
	return packet
}

func (c *ControlString) String() string {
	return fmt.Sprintf("Control Type: %s (%q)  Criticality: %t  Control Value: %s", ControlTypeMap[c.ControlType], c.ControlType, c.Criticality, c.ControlValue)
}

type ControlPaging struct {
	PagingSize uint32
	Cookie     []byte
}

func (c *ControlPaging) GetControlType() string {
	return ControlTypePaging
}

func (c *ControlPaging) Encode() *ber.Packet {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, ControlTypePaging, "Control Type ("+ControlTypeMap[ControlTypePaging]+")"))

	p2 := ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, nil, "Control Value (Paging)")
	seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Search Control Value")
	seq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, uint64(c.PagingSize), "Paging Size"))
	cookie := ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, nil, "Cookie")
	cookie.Value = c.Cookie
	cookie.Data.Write(c.Cookie)
	seq.AppendChild(cookie)
	p2.AppendChild(seq)

	packet.AppendChild(p2)
	return packet
}

func (c *ControlPaging) String() string {
	return fmt.Sprintf(
		"Control Type: %s (%q)  Criticality: %t  PagingSize: %d  Cookie: %q",
		ControlTypeMap[ControlTypePaging],
		ControlTypePaging,
		false,
		c.PagingSize,
		c.Cookie)
}

func (c *ControlPaging) SetCookie(cookie []byte) {
	c.Cookie = cookie
}

func FindControl(controls []Control, controlType string) Control {
	for _, c := range controls {
		if c.GetControlType() == controlType {
			return c
		}
	}
	return nil
}

func DecodeControl(packet *ber.Packet) (control Control, err error) {
	defer func() {
		if r := recover(); r != nil {
			control = nil
			err = fmt.Errorf("ldap: failed to decode control: %v", r)
		}
	}()

	if packet == nil || len(packet.Children) == 0 {
		return nil, fmt.Errorf("ldap: failed to decode control: malformed control packet")
	}
	if packet.Children[0] == nil {
		return nil, fmt.Errorf("ldap: failed to decode control: malformed control packet")
	}
	ControlType, ok := packet.Children[0].Value.(string)
	if !ok {
		return nil, fmt.Errorf("ldap: failed to decode control: malformed control type")
	}
	packet.Children[0].Description = "Control Type (" + ControlTypeMap[ControlType] + ")"
	c := new(ControlString)
	c.ControlType = ControlType
	c.Criticality = false

	if len(packet.Children) > 1 {
		value := packet.Children[1]
		if len(packet.Children) == 3 {
			value = packet.Children[2]
			if packet.Children[1] == nil {
				return nil, fmt.Errorf("ldap: failed to decode control: malformed control criticality")
			}
			packet.Children[1].Description = "Criticality"
			criticality, ok := packet.Children[1].Value.(bool)
			if !ok {
				return nil, fmt.Errorf("ldap: failed to decode control: malformed control criticality")
			}
			c.Criticality = criticality
		}
		if value == nil {
			return nil, fmt.Errorf("ldap: failed to decode control: malformed control value")
		}

		value.Description = "Control Value"
		switch ControlType {
		case ControlTypePaging:
			value.Description += " (Paging)"
			c := new(ControlPaging)
			if value.Value != nil {
				valueChildren := ber.DecodePacket(value.Data.Bytes())
				value.Data.Truncate(0)
				value.Value = nil
				value.AppendChild(valueChildren)
			}
			// Exactly one controlValue, RFC2696
			if len(value.Children) != 1 || value.Children[0] == nil {
				return nil, fmt.Errorf("ldap: failed to decode control: malformed paging control value")
			}
			value = value.Children[0]
			value.Description = "Search Control Value"
			if len(value.Children) < 2 || value.Children[0] == nil || value.Children[1] == nil {
				return nil, fmt.Errorf("ldap: failed to decode control: malformed paging control value")
			}
			value.Children[0].Description = "Paging Size"
			value.Children[1].Description = "Cookie"
			pagingSize, ok := value.Children[0].Value.(int64)
			if !ok || pagingSize < 0 || pagingSize > int64(^uint32(0)) {
				return nil, fmt.Errorf("ldap: failed to decode control: malformed paging control size")
			}
			c.PagingSize = uint32(pagingSize)
			c.Cookie = value.Children[1].Data.Bytes()
			value.Children[1].Value = c.Cookie
			return c, nil
		}
		controlValue, ok := value.Value.(string)
		if !ok {
			return nil, fmt.Errorf("ldap: failed to decode control: malformed control value")
		}
		c.ControlValue = controlValue
	}
	return c, nil
}

func NewControlString(controlType string, criticality bool, controlValue string) *ControlString {
	return &ControlString{
		ControlType:  controlType,
		Criticality:  criticality,
		ControlValue: controlValue,
	}
}

func NewControlPaging(pagingSize uint32) *ControlPaging {
	return &ControlPaging{PagingSize: pagingSize}
}

func encodeControls(controls []Control) *ber.Packet {
	packet := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "Controls")
	for _, control := range controls {
		packet.AppendChild(control.Encode())
	}
	return packet
}
