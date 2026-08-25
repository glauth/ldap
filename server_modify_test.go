package ldaps

import (
	"context"
	"log"
	"net"
	"os/exec"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

func TestAdd(t *testing.T) {
	s := NewServer()
	s.BindFunc("", modifyTestHandler{})
	s.AddFunc("", modifyTestHandler{})
	addr, err := ListenAndServe(t, s)
	if err != nil {
		t.Errorf("Failed to listen")
		return
	}
	t.Cleanup(s.Close)
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ldapadd", "-v", "-H", "ldap://"+addr.String(), "-x", "-f", "tests/add.ldif")

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ldapadd failed: error(%v): %s", err, out)
	}
	if !strings.Contains(string(out), "modify complete") {
		t.Errorf("ldapadd failed: %s", out)
	}
}

func TestAddFail(t *testing.T) {
	previousOutput := log.Writer()
	log.SetOutput(t.Output())

	t.Cleanup(func() { log.SetOutput(previousOutput) })
	s := NewServer()
	s.BindFunc("", modifyTestHandler{})
	s.AddFunc("", modifyTestHandler{})

	addr, err := ListenAndServe(t, s)
	if err != nil {
		t.Errorf("Failed to listen")
		return
	}
	t.Cleanup(s.Close)
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ldapadd", "-v", "-H", "ldap://"+addr.String(), "-x", "-f", "tests/add2.ldif")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Errorf("ldapadd succeed. It shouldn't have: %s", out)
	}
	if !strings.Contains(string(out), "ldap_add: Insufficient access") {
		t.Errorf("ldapadd should have failed: %s", out)
	}
	if strings.Contains(string(out), "modify complete") {
		t.Errorf("ldapadd should have failed: %s", out)
	}
}

func TestDelete(t *testing.T) {
	s := NewServer()
	s.BindFunc("", modifyTestHandler{})
	s.DeleteFunc("", modifyTestHandler{})

	addr, err := ListenAndServe(t, s)
	if err != nil {
		t.Errorf("Failed to listen")
		return
	}
	t.Cleanup(s.Close)
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ldapdelete", "-v", "-H", "ldap://"+addr.String(), "-x", "cn=Delete Me,dc=example,dc=com")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ldapdelete failed: error(%v): %s", err, out)
	}
	if cmd.ProcessState.ExitCode() != 0 {
		t.Errorf("ldapdelete failed: %s", out)
	}
}

func TestDeleteFail(t *testing.T) {
	previousOutput := log.Writer()
	log.SetOutput(t.Output())

	t.Cleanup(func() { log.SetOutput(previousOutput) })
	s := NewServer()
	s.BindFunc("", modifyTestHandler{})
	s.DeleteFunc("", modifyTestHandler{})

	addr, err := ListenAndServe(t, s)
	if err != nil {
		t.Errorf("Failed to listen")
		return
	}
	t.Cleanup(s.Close)
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ldapdelete", "-v", "-H", "ldap://"+addr.String(), "-x", "cn=Bob,dc=example,dc=com")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Errorf("ldapdelete succeed. It shouldn't have: %s", out)
	}
	if strings.Contains(string(out), "Success") || !strings.Contains(string(out), "ldap_delete: Insufficient access") {
		t.Errorf("ldapdelete should have failed: %s", out)
	}
}

func TestModify(t *testing.T) {
	s := NewServer()
	s.BindFunc("", modifyTestHandler{})
	s.ModifyFunc("", modifyTestHandler{})

	addr, err := ListenAndServe(t, s)
	if err != nil {
		t.Errorf("Failed to listen")
		return
	}
	t.Cleanup(s.Close)
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ldapmodify", "-v", "-H", "ldap://"+addr.String(), "-x", "-f", "tests/modify.ldif")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ldapmodify failed: error(%v): %s", err, out) // TODO:
	}
	if !strings.Contains(string(out), "modify complete") {
		t.Errorf("ldapmodify failed: %s", out)
		return
	}
}

func TestModifyFail(t *testing.T) {
	previousOutput := log.Writer()
	log.SetOutput(t.Output())

	t.Cleanup(func() { log.SetOutput(previousOutput) })
	s := NewServer()
	s.BindFunc("", modifyTestHandler{})
	s.ModifyFunc("", modifyTestHandler{})

	addr, err := ListenAndServe(t, s)
	if err != nil {
		t.Errorf("Failed to listen")
		return
	}
	t.Cleanup(s.Close)
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ldapmodify", "-v", "-H", "ldap://"+addr.String(), "-x", "-f", "tests/modify2.ldif")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Errorf("ldapmodify succeed. It shouldn't have: %s", out)
	}
	if !strings.Contains(string(out), "ldap_modify: Insufficient access") || strings.Contains(string(out), "modify complete") {
		t.Errorf("ldapmodify should have failed: %s", out)
		return
	}
}

type modifyTestHandler struct {
}

func (h modifyTestHandler) Bind(bindDN, bindSimplePw string, conn net.Conn) (uint16, error) {
	if bindDN == "" && bindSimplePw == "" {
		return ldap.LDAPResultSuccess, nil
	}
	return ldap.LDAPResultInvalidCredentials, nil
}
func (h modifyTestHandler) Add(boundDN string, req ldap.AddRequest, conn net.Conn) (uint16, error) {
	// only succeed on expected contents of add.ldif:
	if len(req.Attributes) == 5 && req.DN == "cn=Barbara Jensen,dc=example,dc=com" &&
		req.Attributes[2].Type == "sn" && len(req.Attributes[2].Vals) == 1 &&
		req.Attributes[2].Vals[0] == "Jensen" {
		return ldap.LDAPResultSuccess, nil
	}
	return ldap.LDAPResultInsufficientAccessRights, nil
}
func (h modifyTestHandler) Delete(boundDN, deleteDN string, conn net.Conn) (uint16, error) {
	// only succeed on expected deleteDN
	if deleteDN == "cn=Delete Me,dc=example,dc=com" {
		return ldap.LDAPResultSuccess, nil
	}
	return ldap.LDAPResultInsufficientAccessRights, nil
}
func extractChanges(req ldap.ModifyRequest) (deleteAttributes []ldap.Change, replaceAttributes []ldap.Change, addAttributes []ldap.Change, incrementAttributes []ldap.Change, otherAttributes []ldap.Change) {
	for _, change := range req.Changes {
		switch change.Operation {
		case ldap.AddAttribute:
			addAttributes = append(addAttributes, change)
		case ldap.ReplaceAttribute:
			replaceAttributes = append(replaceAttributes, change)
		case ldap.DeleteAttribute:
			deleteAttributes = append(deleteAttributes, change)
		case ldap.IncrementAttribute:
			incrementAttributes = append(incrementAttributes, change)
		default:
			otherAttributes = append(otherAttributes, change)
		}
	}
	return addAttributes, deleteAttributes, replaceAttributes, incrementAttributes, otherAttributes
}
func (h modifyTestHandler) Modify(boundDN string, req ldap.ModifyRequest, conn net.Conn) (uint16, error) {
	// only succeed on expected contents of modify.ldif:
	addAttributes, deleteAttributes, replaceAttributes, incrementAttributes, otherAttributes := extractChanges(req)
	if req.DN == "cn=testy,dc=example,dc=com" &&
		len(incrementAttributes) == 0 &&
		len(otherAttributes) == 0 &&
		len(addAttributes) == 1 &&
		len(deleteAttributes) == 3 &&
		len(replaceAttributes) == 2 &&
		deleteAttributes[2].Modification.Type == "details" &&
		len(deleteAttributes[2].Modification.Vals) == 0 {
		return ldap.LDAPResultSuccess, nil
	}
	return ldap.LDAPResultInsufficientAccessRights, nil
}
func (h modifyTestHandler) ModifyDN(boundDN string, req ldap.ModifyDNRequest, conn net.Conn) (uint16, error) {
	return ldap.LDAPResultInsufficientAccessRights, nil
}
