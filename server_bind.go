package ldaps

import (
	"log"
	"net"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

func HandleBindRequest(req *ber.Packet, fns map[string]Binder, conn net.Conn) (resultCode uint16) {
	defer func() {
		if r := recover(); r != nil {
			resultCode = ldap.LDAPResultOperationsError
		}
	}()

	// we only support ldapv3
	ldapVersion, ok := req.Children[0].Value.(int64)
	if !ok {
		return ldap.LDAPResultProtocolError
	}
	if ldapVersion != 3 {
		log.Printf("Unsupported LDAP version: %d", ldapVersion)
		return ldap.LDAPResultInappropriateAuthentication
	}

	// auth types
	bindDN, ok := req.Children[1].Value.(string)
	if !ok {
		return ldap.LDAPResultProtocolError
	}
	bindAuth := req.Children[2]
	switch bindAuth.Tag {
	default:
		log.Print("Unknown LDAP authentication method")
		return ldap.LDAPResultInappropriateAuthentication
	case LDAPBindAuthSimple:
		if len(req.Children) == 3 {
			fnNames := []string{}
			for k := range fns {
				fnNames = append(fnNames, k)
			}
			fn := routeFunc(bindDN, fnNames)
			resultCode, err := fns[fn].Bind(bindDN, bindAuth.Data.String(), conn)
			if err != nil {
				log.Printf("BindFn Error %v", err)
				return ldap.LDAPResultOperationsError
			}
			return resultCode
		}
		log.Print("Simple bind request has wrong # children.  len(req.Children) != 3")
		return ldap.LDAPResultInappropriateAuthentication
	case LDAPBindAuthSASL:
		log.Print("SASL authentication is not supported")
		return ldap.LDAPResultInappropriateAuthentication
	}
}
