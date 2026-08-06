package ldaps

import (
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

func TestAdd(t *testing.T) {
	done := make(chan bool)
	s := NewServer()
	s.BindFunc("", modifyTestHandler{})
	s.AddFunc("", modifyTestHandler{})
	go func() {
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()
	go func() {
		cmd := exec.Command("ldapadd", "-v", "-H", ldapURL, "-x", "-f", "tests/add.ldif")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "modify complete") {
			t.Errorf("ldapadd failed: %v", string(out))
		}
		cmd = exec.Command("ldapadd", "-v", "-H", ldapURL, "-x", "-f", "tests/add2.ldif")
		out, _ = cmd.CombinedOutput()
		if !strings.Contains(string(out), "ldap_add: Insufficient access") {
			t.Errorf("ldapadd should have failed: %v", string(out))
		}
		if strings.Contains(string(out), "modify complete") {
			t.Errorf("ldapadd should have failed: %v", string(out))
		}
		done <- true
	}()
	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapadd command timed out")
	}
	s.Close()
}

func TestDelete(t *testing.T) {
	done := make(chan bool)
	s := NewServer()
	s.BindFunc("", modifyTestHandler{})
	s.DeleteFunc("", modifyTestHandler{})
	go func() {
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()
	go func() {
		cmd := exec.Command("ldapdelete", "-v", "-H", ldapURL, "-x", "cn=Delete Me,dc=example,dc=com")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "Delete Result: Success (0)") || !strings.Contains(string(out), "Additional info: Success") {
			t.Errorf("ldapdelete failed: %v", string(out))
		}
		cmd = exec.Command("ldapdelete", "-v", "-H", ldapURL, "-x", "cn=Bob,dc=example,dc=com")
		out, _ = cmd.CombinedOutput()
		if strings.Contains(string(out), "Success") || !strings.Contains(string(out), "ldap_delete: Insufficient access") {
			t.Errorf("ldapdelete should have failed: %v", string(out))
		}
		done <- true
	}()
	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapdelete command timed out")
	}
	s.Close()
}

func TestModify(t *testing.T) {
	done := make(chan bool)
	s := NewServer()
	s.BindFunc("", modifyTestHandler{})
	s.ModifyFunc("", modifyTestHandler{})
	go func() {
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()
	go func() {
		cmd := exec.Command("ldapmodify", "-v", "-H", ldapURL, "-x", "-f", "tests/modify.ldif")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "modify complete") {
			t.Errorf("ldapmodify failed: %v", string(out))
		}
		cmd = exec.Command("ldapmodify", "-v", "-H", ldapURL, "-x", "-f", "tests/modify2.ldif")
		out, _ = cmd.CombinedOutput()
		if !strings.Contains(string(out), "ldap_modify: Insufficient access") || strings.Contains(string(out), "modify complete") {
			t.Errorf("ldapmodify should have failed: %v", string(out))
		}
		done <- true
	}()
	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapadd command timed out")
	}
	s.Close()
}

/*
func TestModifyDN(t *testing.T) {
	quit := make(chan bool)
	done := make(chan bool)
	go func() {
		s := NewServer()
		s.QuitChannel(quit)
		s.BindFunc("", modifyTestHandler{})
		s.AddFunc("", modifyTestHandler{})
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()
	go func() {
		cmd := exec.Command("ldapadd", "-v", "-H", ldapURL, "-x", "-f", "tests/add.ldif")
		//ldapmodrdn -H ldap://localhost:3389 -x "uid=babs,dc=example,dc=com" "uid=babsy,dc=example,dc=com"
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "modify complete") {
			t.Errorf("ldapadd failed: %v", string(out))
		}
		cmd = exec.Command("ldapadd", "-v", "-H", ldapURL, "-x", "-f", "tests/add2.ldif")
		out, _ = cmd.CombinedOutput()
		if !strings.Contains(string(out), "ldap_add: Insufficient access") {
			t.Errorf("ldapadd should have failed: %v", string(out))
		}
		if strings.Contains(string(out), "modify complete") {
			t.Errorf("ldapadd should have failed: %v", string(out))
		}
		done <- true
	}()
	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapadd command timed out")
	}
	quit <- true
}
*/

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
