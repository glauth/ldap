package ldaps

import (
	"context"
	"errors"
	"fmt"
	"net"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

var ErrInvalidPacketLength = errors.New("invalid packet length")

func HandleAddRequest(ctx context.Context, req *ber.Packet, boundDN string, fns map[string]Adder, conn net.Conn) error {
	if len(req.Children) != 2 {
		return fmt.Errorf("error invalid %v: no attributes sent: %w", ldap.ApplicationMap[uint8(req.Tag)], ldap.NewError(ldap.LDAPResultProtocolError, ErrInvalidPacketLength))
	}
	var ok bool
	addReq := ldap.AddRequest{}
	addReq.DN, ok = req.Children[0].Value.(string)
	if !ok {
		return ldap.NewError(ldap.LDAPResultProtocolError, fmt.Errorf("error reading DN: %v", req.Children[0].Value))
	}
	addReq.Attributes = []ldap.Attribute{}
	for _, attr := range req.Children[1].Children {
		if len(attr.Children) != 2 {
			return fmt.Errorf("error invalid %v: no attributes sent: %w", ldap.ApplicationMap[uint8(req.Tag)], ldap.NewError(ldap.LDAPResultProtocolError, ErrInvalidPacketLength))
		}

		a := ldap.Attribute{}
		a.Type, ok = attr.Children[0].Value.(string)
		if !ok {
			return ldap.NewError(ldap.LDAPResultProtocolError, fmt.Errorf("error reading attribute name: %v", attr.Children[0].Value))
		}
		a.Vals = []string{}
		for _, val := range attr.Children[1].Children {
			v, ok := val.Value.(string)
			if !ok {
				return ldap.NewError(ldap.LDAPResultProtocolError, fmt.Errorf("error reading attribute value: %v", attr.Children[1].Value))
			}
			a.Vals = append(a.Vals, v)
		}
		addReq.Attributes = append(addReq.Attributes, a)
	}
	fnNames := []string{}
	for k := range fns {
		fnNames = append(fnNames, k)
	}
	fn := routeFunc(boundDN, fnNames)

	return fns[fn].Add(ctx, boundDN, addReq, conn)
}

func HandleDeleteRequest(ctx context.Context, req *ber.Packet, boundDN string, fns map[string]Deleter, conn net.Conn) error {
	deleteDN := ber.DecodeString(req.Data.Bytes())
	fnNames := []string{}
	for k := range fns {
		fnNames = append(fnNames, k)
	}
	fn := routeFunc(boundDN, fnNames)

	return fns[fn].Delete(ctx, boundDN, deleteDN, conn)
}

func HandleModifyRequest(ctx context.Context, req *ber.Packet, boundDN string, fns map[string]Modifier, conn net.Conn) (*ldap.ModifyResult, error) {
	if len(req.Children) != 2 {
		return nil, fmt.Errorf("error invalid %v: no attributes sent: %w", ldap.ApplicationMap[uint8(req.Tag)], ldap.NewError(ldap.LDAPResultProtocolError, ErrInvalidPacketLength))
	}
	var ok bool
	modReq := ldap.ModifyRequest{}
	modReq.DN, ok = req.Children[0].Value.(string)
	if !ok {
		return nil, ldap.NewError(ldap.LDAPResultProtocolError, fmt.Errorf("error reading DN: %v", req.Children[0].Value))
	}
	for _, change := range req.Children[1].Children {
		if len(change.Children) != 2 {
			return nil, fmt.Errorf("error invalid %v: no attributes sent: %w", ldap.ApplicationMap[uint8(req.Tag)], ldap.NewError(ldap.LDAPResultProtocolError, ErrInvalidPacketLength))
		}
		attr := ldap.PartialAttribute{}
		attrs := change.Children[1].Children
		if len(attrs) != 2 {
			return nil, fmt.Errorf("error invalid %v: no attributes sent: %w", ldap.ApplicationMap[uint8(req.Tag)], ldap.NewError(ldap.LDAPResultProtocolError, ErrInvalidPacketLength))
		}

		attr.Type, ok = attrs[0].Value.(string)
		if !ok {
			return nil, ldap.NewError(ldap.LDAPResultProtocolError, fmt.Errorf("error reading modify attribute name: %v", attrs[0].Value))
		}
		for _, val := range attrs[1].Children {
			v, ok := val.Value.(string)
			if !ok {
				return nil, ldap.NewError(ldap.LDAPResultProtocolError, fmt.Errorf("error reading modify attribute value: %v", val.Value))
			}
			attr.Vals = append(attr.Vals, v)
		}
		op, ok := change.Children[0].Value.(int64)
		if !ok {
			return nil, ldap.NewError(ldap.LDAPResultProtocolError, fmt.Errorf("error reading modify operation type: %v", change.Children[0].Value))
		}
		switch op {
		default:
			return nil, ldap.NewError(ldap.LDAPResultProtocolError, fmt.Errorf("unrecognized modify attribute %d", op))
		case ldap.AddAttribute:
			modReq.Add(attr.Type, attr.Vals)
		case ldap.DeleteAttribute:
			modReq.Delete(attr.Type, attr.Vals)
		case ldap.ReplaceAttribute:
			modReq.Replace(attr.Type, attr.Vals)
		}
	}
	fnNames := []string{}
	for k := range fns {
		fnNames = append(fnNames, k)
	}
	fn := routeFunc(boundDN, fnNames)

	return fns[fn].Modify(ctx, boundDN, modReq, conn)
}

func HandleCompareRequest(ctx context.Context, req *ber.Packet, boundDN string, fns map[string]Comparer, conn net.Conn) error {
	if len(req.Children) != 2 {
		return fmt.Errorf("error invalid %v: no attributes sent: %w", ldap.ApplicationMap[uint8(req.Tag)], ldap.NewError(ldap.LDAPResultProtocolError, ErrInvalidPacketLength))
	}

	var (
		ok      bool
		compReq ldap.CompareRequest
	)

	compReq.DN, ok = req.Children[0].Value.(string)
	if !ok {
		return ldap.NewError(ldap.LDAPResultProtocolError, fmt.Errorf("error reading compare DN: %v", req.Children[0].Value))
	}

	ava := req.Children[1]
	if len(ava.Children) != 2 {
		return fmt.Errorf("error invalid %v: no attributes sent: %w", ldap.ApplicationMap[uint8(req.Tag)], ldap.NewError(ldap.LDAPResultProtocolError, ErrInvalidPacketLength))
	}

	attr, ok := ava.Children[0].Value.(string)
	if !ok {
		return ldap.NewError(ldap.LDAPResultProtocolError, fmt.Errorf("error reading compare attribute name: %v", ava.Children[0].Value))
	}

	val, ok := ava.Children[1].Value.(string)
	if !ok {
		return ldap.NewError(ldap.LDAPResultProtocolError, fmt.Errorf("error reading compare attribute value: %v", ava.Children[1].Value))
	}
	compReq.Attribute = attr
	compReq.Value = val
	fnNames := []string{}
	for k := range fns {
		fnNames = append(fnNames, k)
	}
	fn := routeFunc(boundDN, fnNames)

	return fns[fn].Compare(ctx, boundDN, compReq, conn)
}

func HandleExtendedRequest(ctx context.Context, req *ber.Packet, boundDN string, fns map[string]Extender, conn net.Conn) error {
	if len(req.Children) != 1 && len(req.Children) != 2 {
		return fmt.Errorf("error invalid %v: no attributes sent: %w", ldap.ApplicationMap[uint8(req.Tag)], ldap.NewError(ldap.LDAPResultProtocolError, ErrInvalidPacketLength))
	}
	name := ber.DecodeString(req.Children[0].Data.Bytes())
	extReq := ldap.ExtendedRequest{Name: name, Value: req}
	fnNames := []string{}
	for k := range fns {
		fnNames = append(fnNames, k)
	}
	fn := routeFunc(boundDN, fnNames)
	return fns[fn].Extended(ctx, boundDN, extReq, conn)
}

func HandleAbandonRequest(ctx context.Context, req *ber.Packet, boundDN string, fns map[string]Abandoner, conn net.Conn) error {
	fnNames := []string{}
	for k := range fns {
		fnNames = append(fnNames, k)
	}
	fn := routeFunc(boundDN, fnNames)

	return fns[fn].Abandon(ctx, boundDN, conn)
}

func HandleModifyDNRequest(ctx context.Context, req *ber.Packet, boundDN string, fns map[string]ModifyDNr, conn net.Conn) error {
	if len(req.Children) != 3 && len(req.Children) != 4 {
		return fmt.Errorf("error invalid %v: no attributes sent: %w", ldap.ApplicationMap[uint8(req.Tag)], ldap.NewError(ldap.LDAPResultProtocolError, ErrInvalidPacketLength))
	}
	var ok bool
	mdnReq := ldap.ModifyDNRequest{}
	mdnReq.DN, ok = req.Children[0].Value.(string)
	if !ok {
		return ldap.NewError(ldap.LDAPResultProtocolError, fmt.Errorf("error reading DN: %v", req.Children[0].Value))
	}
	mdnReq.NewRDN, ok = req.Children[1].Value.(string)
	if !ok {
		return ldap.NewError(ldap.LDAPResultProtocolError, fmt.Errorf("error reading new RDN: %v", req.Children[1].Value))
	}
	mdnReq.DeleteOldRDN, ok = req.Children[2].Value.(bool)
	if !ok {
		return ldap.NewError(ldap.LDAPResultProtocolError, fmt.Errorf("error reading DeleteOldRDN: %v", req.Children[2].Value))
	}
	if len(req.Children) == 4 {
		mdnReq.NewSuperior, ok = req.Children[3].Value.(string)
		if !ok {
			return ldap.NewError(ldap.LDAPResultProtocolError, fmt.Errorf("error reading NewSuperior: %v", req.Children[3].Value))
		}
	}
	fnNames := []string{}
	for k := range fns {
		fnNames = append(fnNames, k)
	}
	fn := routeFunc(boundDN, fnNames)

	return fns[fn].ModifyDN(ctx, boundDN, mdnReq, conn)
}
