package ldaps

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"runtime/debug"
	"strings"
	"sync"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

const (
	LDAPBindAuthSimple = 0
	LDAPBindAuthSASL   = 3
	oidStartTLS        = "1.3.6.1.4.1.1466.20037"
)

var (
	ErrEmpty          = errors.New("")
	ErrInternal       = errors.New("internal error")
	ErrNotImplemented = errors.New("not implemented")
)

type Binder interface {
	Bind(bindDN, bindSimplePw string, conn net.Conn) (*ldap.SimpleBindResult, error)
}
type Searcher interface {
	Search(boundDN string, req ldap.SearchRequest, conn net.Conn) (*ldap.SearchResult, error)
}
type Extender interface {
	Extended(boundDN string, req ldap.ExtendedRequest, conn net.Conn) error
}
type Abandoner interface {
	Abandon(boundDN string, conn net.Conn) error
}
type Adder interface {
	Add(boundDN string, req ldap.AddRequest, conn net.Conn) error
}
type Modifier interface {
	Modify(boundDN string, req ldap.ModifyRequest, conn net.Conn) (*ldap.ModifyResult, error)
}
type Deleter interface {
	Delete(boundDN, deleteDN string, conn net.Conn) error
}
type ModifyDNr interface {
	ModifyDN(boundDN string, req ldap.ModifyDNRequest, conn net.Conn) error
}
type Comparer interface {
	Compare(boundDN string, req ldap.CompareRequest, conn net.Conn) error
}
type Closer interface {
	Close(boundDN string, conn net.Conn)
}

type Server struct {
	BindFns     map[string]Binder
	SearchFns   map[string]Searcher
	AddFns      map[string]Adder
	ModifyFns   map[string]Modifier
	DeleteFns   map[string]Deleter
	ModifyDNFns map[string]ModifyDNr
	CompareFns  map[string]Comparer
	AbandonFns  map[string]Abandoner
	ExtendedFns map[string]Extender
	CloseFns    map[string]Closer
	Context     context.Context
	cancel      func()
	EnforceLDAP bool
	stats       *stats
	ln          net.Listener

	// If set, server will accept StartTLS.
	TLSConfig *tls.Config
}

type Stats struct {
	Conns          int
	Binds          int
	Unbinds        int
	Searches       int
	NotImplemented int
}

type stats struct {
	Stats
	statsMutex sync.Mutex
}

func NewServer() *Server {
	return NewServerContext(context.Background())
}

func NewServerContext(ctx context.Context) *Server {
	s := new(Server)
	s.Context, s.cancel = context.WithCancel(ctx)

	s.BindFns = make(map[string]Binder)
	s.SearchFns = make(map[string]Searcher)
	s.ExtendedFns = make(map[string]Extender)
	s.AbandonFns = make(map[string]Abandoner)
	s.AddFns = make(map[string]Adder)
	s.ModifyFns = make(map[string]Modifier)
	s.DeleteFns = make(map[string]Deleter)
	s.ModifyDNFns = make(map[string]ModifyDNr)
	s.CompareFns = make(map[string]Comparer)
	s.CloseFns = make(map[string]Closer)

	d := defaultHandler{}
	s.BindFunc("", d)
	s.SearchFunc("", d)
	s.ExtendedFunc("", d)
	s.AbandonFunc("", d)
	s.AddFunc("", d)
	s.ModifyFunc("", d)
	s.DeleteFunc("", d)
	s.ModifyDNFunc("", d)
	s.CompareFunc("", d)
	s.CloseFunc("", d)
	s.stats = nil
	return s
}

func (server *Server) BindFunc(baseDN string, f Binder) {
	server.BindFns[baseDN] = f
}

func (server *Server) SearchFunc(baseDN string, f Searcher) {
	server.SearchFns[baseDN] = f
}

func (server *Server) AddFunc(baseDN string, f Adder) {
	server.AddFns[baseDN] = f
}

func (server *Server) ModifyFunc(baseDN string, f Modifier) {
	server.ModifyFns[baseDN] = f
}

func (server *Server) DeleteFunc(baseDN string, f Deleter) {
	server.DeleteFns[baseDN] = f
}

func (server *Server) ModifyDNFunc(baseDN string, f ModifyDNr) {
	server.ModifyDNFns[baseDN] = f
}

func (server *Server) CompareFunc(baseDN string, f Comparer) {
	server.CompareFns[baseDN] = f
}

func (server *Server) AbandonFunc(baseDN string, f Abandoner) {
	server.AbandonFns[baseDN] = f
}

func (server *Server) ExtendedFunc(baseDN string, f Extender) {
	server.ExtendedFns[baseDN] = f
}

func (server *Server) CloseFunc(baseDN string, f Closer) {
	server.CloseFns[baseDN] = f
}

func (server *Server) SetStats(enable bool) {
	if enable {
		server.stats = &stats{}
	} else {
		server.stats = nil
	}
}

func (server *Server) GetStats() Stats {
	defer server.stats.statsMutex.Unlock()
	server.stats.statsMutex.Lock()

	return server.stats.Stats
}

func (server *Server) ListenAndServe(listenString string) error {
	ln, err := net.Listen("tcp", listenString)
	if err != nil {
		return err
	}

	return server.Serve(ln)
}

func (server *Server) Serve(ln net.Listener) error {
	server.ln = ln
	newConn := make(chan net.Conn)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				if !errors.Is(err, net.ErrClosed) {
					log.Printf("Error accepting network connection: %v", err)
				}
				break
			}
			newConn <- conn
		}
	}()

listener:
	for {
		select {
		case c := <-newConn:
			server.stats.countConns(1)
			go server.handleConnection(c)
		case <-server.Context.Done():
			server.cancel = nil
			server.Close()
			break listener
		}
	}
	return nil
}

// Close closes the underlying net.Listener, and waits for confirmation
func (server *Server) Close() {
	if server.ln != nil {
		server.ln.Close()
		server.ln = nil
	}
	if server.cancel != nil {
		server.cancel()
	}
}

func handleCloseFunc(fnName string, closeFn Closer, boundDN string, conn net.Conn) {
	defer func() {
		panicResult := recover()
		if panicResult != nil {
			log.Printf("Recovered from panic in handleClose(%s): %s\n%s", fnName, panicResult, string(debug.Stack()))
		}
	}()
	closeFn.Close(boundDN, conn)
}

func handleClose(fns map[string]Closer, boundDN string, conn net.Conn) {
	for fnName, closeFn := range fns {
		handleCloseFunc(fnName, closeFn, boundDN, conn)
	}
}

func (server *Server) handleConnection(conn net.Conn) {
	boundDN := "" // "" == anonymous
	defer func() {
		panicResult := recover()
		if panicResult != nil {
			log.Printf("Recovered from panic in handleConnection: %s\n%s", panicResult, string(debug.Stack()))
		}

		handleClose(server.CloseFns, boundDN, conn)
		conn.Close()
	}()
handler:
	for {
		// read incoming LDAP packet
		packet, err := ber.ReadPacket(conn)
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) { // Client closed connection
			break
		} else if err != nil {
			log.Printf("handleConnection ber.ReadPacket ERROR: %v", err)
			break
		}

		// sanity check this packet
		if len(packet.Children) < 2 {
			log.Print("len(packet.Children) < 2")
			break
		}
		// check the message ID and ClassType
		messageID64, ok := packet.Children[0].Value.(int64)
		if !ok {
			log.Print("malformed messageID")
			break
		}
		messageID := uint64(messageID64)
		req := packet.Children[1]
		if req.ClassType != ber.ClassApplication {
			log.Print("req.ClassType != ber.ClassApplication")
			break
		}
		// handle controls if present
		controls := []ldap.Control{}
		if len(packet.Children) > 2 {
			for _, child := range packet.Children[2].Children {
				control, err := ldap.DecodeControl(child)
				if err != nil {
					log.Printf("DecodeControl error %v", err)
					responsePacket := encodeProtocolErrorResponse(messageID, req.Tag, "", nil)
					if responsePacket != nil {
						if err = sendPacket(conn, responsePacket); err != nil {
							log.Printf("sendPacket error %v", err)
						}
					}
					break handler
				}
				controls = append(controls, control)
			}
		}

		// dispatch the LDAP operation
		switch req.Tag { // ldap op code
		default:
			name, ok := ldap.ApplicationMap[uint8(req.Tag)]
			if !ok {
				name = "Unknown"
			}
			log.Printf("Unhandled operation: %s [%d]", name, req.Tag)
			responsePacket := encodeLDAPResponse(messageID, ldap.ApplicationAddResponse, ldap.LDAPResultUnavailable, fmt.Sprintf("Unhandled operation: %s [%d]", name, req.Tag), nil)
			if err = sendPacket(conn, responsePacket); err != nil {
				log.Printf("sendPacket error %s", err.Error())
			}

			break handler

		case ldap.ApplicationBindRequest:
			server.stats.countBinds(1)
			dn, _, err := HandleBindRequest(req, server.BindFns, conn) // TODO: Handle SimpleBindResult
			resultCode, message := StatusResult(err)

			if resultCode == ldap.LDAPResultSuccess {
				boundDN = dn
			} else {
				log.Printf("Error Binding: %s", err)
			}

			if err = sendPacket(conn, encodeLDAPResponse(messageID, ldap.ApplicationBindResponse, resultCode, message, nil)); err != nil {
				log.Printf("sendPacket error: %s", err.Error())
				boundDN = ""
				break handler
			}
		case ldap.ApplicationSearchRequest:
			server.stats.countSearches(1)
			err = HandleSearchRequest(req, &controls, messageID, boundDN, server, conn)
			resultCode, message := StatusResult(err)
			if resultCode != ldap.LDAPResultSuccess {
				log.Printf("Error Searching: %s", err)
			}
			supportedControls := false
			for _, control := range controls {
				if control.GetControlType() == ldap.ControlTypePaging {
					supportedControls = true
					break
				}
			}
			if !(supportedControls && resultCode == ldap.LDAPResultSuccess) {
				controls = nil
			}

			if err = sendPacket(conn, encodeLDAPResponse(messageID, ldap.ApplicationSearchResultDone, resultCode, message, controls)); err != nil {
				log.Printf("sendPacket error: %s", err.Error())

				break handler
			}
		case ldap.ApplicationUnbindRequest:
			server.stats.countUnbinds(1)
			break handler // simply disconnect
		case ldap.ApplicationExtendedRequest:
			var tlsConn net.Conn
			if len(req.Children) > 0 && ber.DecodeString(req.Children[0].Data.Bytes()) == oidStartTLS {
				if server.TLSConfig != nil {
					tlsConn = tls.Server(conn, server.TLSConfig)
					err = nil
				} else {
					err = ldap.NewError(ldap.LDAPResultUnavailable, errors.New("TLS not configured"))
				}
				fmt.Println(conn, err)
			} else {
				// Wasn't an upgrade. Pass through.
				err = HandleExtendedRequest(req, boundDN, server.ExtendedFns, conn)
			}
			resultCode, message := StatusResult(err)

			if resultCode != ldap.LDAPResultSuccess {
				log.Printf("Error with extended request: %s", err)
			}

			responsePacket := encodeLDAPResponse(messageID, ldap.ApplicationExtendedResponse, resultCode, message, nil)
			if err = sendPacket(conn, responsePacket); err != nil {
				log.Printf("sendPacket error %v", err)
				break handler
			}
			if tlsConn != nil {
				conn = tlsConn
			}
		case ldap.ApplicationAbandonRequest:
			err = HandleAbandonRequest(req, boundDN, server.AbandonFns, conn)
			// We don't need to do any extra handling here abandon does not expect a response
			if err != nil {
				log.Printf("Error Abandoning Request: %s", err)
				break handler
			}
			break handler

		case ldap.ApplicationAddRequest:
			err = HandleAddRequest(req, boundDN, server.AddFns, conn)
			resultCode, message := StatusResult(err)

			if err = sendPacket(conn, encodeLDAPResponse(messageID, ldap.ApplicationAddResponse, resultCode, message, nil)); err != nil {
				log.Printf("sendPacket error: %s", err.Error())

				break handler
			}
		case ldap.ApplicationModifyRequest:
			_, err = HandleModifyRequest(req, boundDN, server.ModifyFns, conn) // TODO: Handle ModifyResult
			resultCode, message := StatusResult(err)

			if resultCode != ldap.LDAPResultSuccess {
				log.Printf("Error Modifying: %s", err)
			}

			if err = sendPacket(conn, encodeLDAPResponse(messageID, ldap.ApplicationModifyResponse, resultCode, message, nil)); err != nil {
				log.Printf("sendPacket error: %s", err.Error())

				break handler
			}
		case ldap.ApplicationDelRequest:
			err = HandleDeleteRequest(req, boundDN, server.DeleteFns, conn)
			resultCode, message := StatusResult(err)

			if resultCode != ldap.LDAPResultSuccess {
				log.Printf("Error Deleting: %s", err)
			}

			if err = sendPacket(conn, encodeLDAPResponse(messageID, ldap.ApplicationDelResponse, resultCode, message, nil)); err != nil {
				log.Printf("sendPacket error: %s", err.Error())

				break handler
			}
		case ldap.ApplicationModifyDNRequest:
			err = HandleModifyDNRequest(req, boundDN, server.ModifyDNFns, conn)
			resultCode, message := StatusResult(err)

			if resultCode != ldap.LDAPResultSuccess && resultCode != ldap.LDAPResultCompareFalse && resultCode != ldap.LDAPResultCompareTrue {
				log.Printf("Error Modifying DN: %s", err)
			}

			if err = sendPacket(conn, encodeLDAPResponse(messageID, ldap.ApplicationModifyDNResponse, resultCode, message, nil)); err != nil {
				log.Printf("sendPacket error: %s", err.Error())

				break handler
			}
		case ldap.ApplicationCompareRequest:
			err = HandleCompareRequest(req, boundDN, server.CompareFns, conn)
			resultCode, message := StatusResult(err)

			if err = sendPacket(conn, encodeLDAPResponse(messageID, ldap.ApplicationCompareResponse, resultCode, message, nil)); err != nil {
				log.Printf("sendPacket error: %s", err.Error())

				break handler
			}
		}
	}
}

func sendPacket(conn net.Conn, packet *ber.Packet) error {
	_, err := conn.Write(packet.Bytes())
	if err != nil {
		log.Printf("Error Sending Message: %v", err)
		return err
	}
	return nil
}

func encodeProtocolErrorResponse(messageID uint64, requestType ber.Tag, message string, controls []ldap.Control) *ber.Packet {
	switch requestType {
	case ldap.ApplicationSearchRequest:
		return encodeLDAPResponse(messageID, ldap.ApplicationSearchResultDone, ldap.LDAPResultProtocolError, message, controls)
	case ldap.ApplicationBindRequest, ldap.ApplicationModifyRequest, ldap.ApplicationAddRequest, ldap.ApplicationDelRequest, ldap.ApplicationModifyDNRequest, ldap.ApplicationCompareRequest, ldap.ApplicationExtendedRequest:
		return encodeLDAPResponse(messageID, uint8(requestType+1), ldap.LDAPResultProtocolError, message, controls)
	default:
		return nil
	}
}

func routeFunc(dn string, funcNames []string) string {
	bestPick := ""
	bestPickWeight := 0
	dnMatch := "," + strings.ToLower(dn)
	var weight int
	for _, fn := range funcNames {
		if strings.HasSuffix(dnMatch, ","+fn) {
			//  empty string as 0, no-comma string 1 , etc
			if fn == "" {
				weight = 0
			} else {
				weight = strings.Count(fn, ",") + 1
			}
			if weight > bestPickWeight {
				bestPick = fn
				bestPickWeight = weight
			}
		}
	}
	return bestPick
}

func StatusResult(err error) (uint16, string) {
	var (
		code    uint16 = ldap.LDAPResultSuccess
		message string
	)
	if err == nil {
		return code, message
	}
	e := &ldap.Error{}
	if !errors.As(err, &e) {
		e = &ldap.Error{ResultCode: ldap.LDAPResultOther, Err: ErrInternal}
	}
	// we can end up with e == nil if we pass the output of ApplyFilter which returns *ldap.ErrorType because errors.As will match on type
	if e == nil {
		return code, message
	}
	code = e.ResultCode
	if e.Err != nil {
		// TODO: use err.Error instead
		message = e.Err.Error()
	}
	return code, message
}

func StatusCode(err error) uint16 {
	code, _ := StatusResult(err)
	return code
}

func encodeLDAPResponse(messageID uint64, responseType uint8, ldapResultCode uint16, message string, controls []ldap.Control) *ber.Packet {
	responsePacket := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
	responsePacket.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "Message ID"))
	response := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ber.Tag(responseType), nil, ldap.ApplicationMap[responseType])
	response.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, uint64(ldapResultCode), "resultCode: "))
	response.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN: "))
	response.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, message, "errorMessage: "))
	responsePacket.AppendChild(response)

	if len(controls) > 0 {
		controlPacket := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "Controls")
		for _, control := range controls {
			controlPacket.AppendChild(control.Encode())
		}
		responsePacket.AppendChild(controlPacket)
	}
	return responsePacket
}

type defaultHandler struct{}

func (h defaultHandler) Bind(bindDN, bindSimplePw string, conn net.Conn) (*ldap.SimpleBindResult, error) {
	return nil, ldap.NewError(ldap.LDAPResultUnavailable, ErrNotImplemented)
}

func (h defaultHandler) Search(boundDN string, req ldap.SearchRequest, conn net.Conn) (*ldap.SearchResult, error) {
	return nil, ldap.NewError(ldap.LDAPResultUnavailable, ErrNotImplemented)
}

func (h defaultHandler) Modify(boundDN string, req ldap.ModifyRequest, conn net.Conn) (*ldap.ModifyResult, error) {
	return nil, ldap.NewError(ldap.LDAPResultUnavailable, ErrNotImplemented)
}

func (h defaultHandler) Add(boundDN string, req ldap.AddRequest, conn net.Conn) error {
	return ldap.NewError(ldap.LDAPResultUnavailable, ErrNotImplemented)
}

func (h defaultHandler) Delete(boundDN, deleteDN string, conn net.Conn) error {
	return ldap.NewError(ldap.LDAPResultUnavailable, ErrNotImplemented)
}

func (h defaultHandler) ModifyDN(boundDN string, req ldap.ModifyDNRequest, conn net.Conn) error {
	return ldap.NewError(ldap.LDAPResultUnavailable, ErrNotImplemented)
}

func (h defaultHandler) Compare(boundDN string, req ldap.CompareRequest, conn net.Conn) error {
	return ldap.NewError(ldap.LDAPResultUnavailable, ErrNotImplemented)
}

func (h defaultHandler) Abandon(boundDN string, conn net.Conn) error {
	return ldap.NewError(ldap.LDAPResultUnavailable, ErrNotImplemented)
}

func (h defaultHandler) Extended(boundDN string, req ldap.ExtendedRequest, conn net.Conn) error {
	return ldap.NewError(ldap.LDAPResultUnavailable, ErrNotImplemented)
}

func (h defaultHandler) Close(boundDN string, conn net.Conn) {} // conn will be closed automatically

func (stats *stats) countConns(delta int) {
	if stats != nil {
		stats.statsMutex.Lock()
		stats.Conns += delta
		stats.statsMutex.Unlock()
	}
}

func (stats *stats) countBinds(delta int) {
	if stats != nil {
		stats.statsMutex.Lock()
		stats.Binds += delta
		stats.statsMutex.Unlock()
	}
}

func (stats *stats) countUnbinds(delta int) {
	if stats != nil {
		stats.statsMutex.Lock()
		stats.Unbinds += delta
		stats.statsMutex.Unlock()
	}
}

func (stats *stats) countSearches(delta int) {
	if stats != nil {
		stats.statsMutex.Lock()
		stats.Searches += delta
		stats.statsMutex.Unlock()
	}
}

func (stats *stats) countNotImplemented(delta int) {
	if stats != nil {
		stats.statsMutex.Lock()
		stats.NotImplemented += delta
		stats.statsMutex.Unlock()
	}
}
