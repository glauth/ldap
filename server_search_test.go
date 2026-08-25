package ldaps

import (
	"context"
	"log"
	"os/exec"
	"strings"
	"testing"
)

func TestSearchSimpleOK(t *testing.T) {
	s := NewServer()
	s.SearchFunc("", searchSimple{})
	s.BindFunc("", bindSimple{})

	addr, err := ListenAndServe(t, s)
	if err != nil {
		t.Fatalf("Failed to listen")
	}
	t.Cleanup(s.Close)
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ldapsearch", "-H", "ldap://"+addr.String(), "-x",
		"-b", serverBaseDN, "-D", "cn=testy,"+serverBaseDN, "-w", "iLike2test")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ldapsearch failed: %v", err)
	}
	if !strings.Contains(string(out), "dn: cn=ned,o=testers,c=test") {
		t.Errorf("ldapsearch failed: %s", out)
	}
	if !strings.Contains(string(out), "uidNumber: 5000") {
		t.Errorf("ldapsearch failed: %s", out)
	}
	if !strings.Contains(string(out), "result: 0 Success") {
		t.Errorf("ldapsearch failed: %s", out)
	}
	if !strings.Contains(string(out), "numResponses: 4") {
		t.Errorf("ldapsearch failed: %s", out)
	}
}

func TestSearchSizelimit(t *testing.T) {
	s := NewServer()
	s.EnforceLDAP = true
	s.SearchFunc("", searchSimple{})
	s.BindFunc("", bindSimple{})

	addr, err := ListenAndServe(t, s)
	if err != nil {
		t.Fatalf("Failed to listen")
	}
	t.Cleanup(s.Close)
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ldapsearch", "-H", "ldap://"+addr.String(), "-x",
		"-b", serverBaseDN, "-D", "cn=testy,"+serverBaseDN, "-w", "iLike2test") // no limit for this test
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ldapsearch failed: %v", err)
	}
	if !strings.Contains(string(out), "result: 0 Success") {
		t.Errorf("ldapsearch failed: %s", out)
	}
	if !strings.Contains(string(out), "numEntries: 3") {
		t.Errorf("ldapsearch sizelimit unlimited failed - not enough entries: %s", out)
	}

	cmd = exec.CommandContext(ctx, "ldapsearch", "-H", "ldap://"+addr.String(), "-x",
		"-b", serverBaseDN, "-D", "cn=testy,"+serverBaseDN, "-w", "iLike2test", "-z", "9") // effectively no limit for this test
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ldapsearch failed: %v", err)
	}
	if !strings.Contains(string(out), "result: 0 Success") {
		t.Errorf("ldapsearch failed: %s", out)
	}
	if !strings.Contains(string(out), "numEntries: 3") {
		t.Errorf("ldapsearch sizelimit 9 failed - not enough entries: %s", out)
	}

	cmd = exec.CommandContext(ctx, "ldapsearch", "-H", "ldap://"+addr.String(), "-x",
		"-b", serverBaseDN, "-D", "cn=testy,"+serverBaseDN, "-w", "iLike2test", "-z", "2")
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ldapsearch failed: %v", err)
	}
	if !strings.Contains(string(out), "result: 0 Success") {
		t.Errorf("ldapsearch failed: %s", out)
	}
	if !strings.Contains(string(out), "numEntries: 2") {
		t.Errorf("ldapsearch sizelimit 2 failed - too many entries: %s", out)
	}

	cmd = exec.CommandContext(ctx, "ldapsearch", "-H", "ldap://"+addr.String(), "-x",
		"-b", serverBaseDN, "-D", "cn=testy,"+serverBaseDN, "-w", "iLike2test", "-z", "1")
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ldapsearch failed: %v", err)
		return
	}
	if !strings.Contains(string(out), "result: 0 Success") {
		t.Errorf("ldapsearch failed: %s", out)
	}
	if !strings.Contains(string(out), "numEntries: 1") {
		t.Errorf("ldapsearch sizelimit 1 failed - too many entries: %s", out)
	}

	cmd = exec.CommandContext(ctx, "ldapsearch", "-H", "ldap://"+addr.String(), "-x",
		"-b", serverBaseDN, "-D", "cn=testy,"+serverBaseDN, "-w", "iLike2test", "-z", "0")
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ldapsearch failed: %v", err)
	}
	if !strings.Contains(string(out), "result: 0 Success") {
		t.Errorf("ldapsearch failed: %s", out)
	}
	if !strings.Contains(string(out), "numEntries: 3") {
		t.Errorf("ldapsearch sizelimit 0 failed - wrong number of entries: %s", out)
	}

	cmd = exec.CommandContext(ctx, "ldapsearch", "-H", "ldap://"+addr.String(), "-x",
		"-b", serverBaseDN, "-D", "cn=testy,"+serverBaseDN, "-w", "iLike2test", "-z", "1", "(uid=trent)")
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ldapsearch failed: %v", err)
	}
	if !strings.Contains(string(out), "result: 0 Success") {
		t.Errorf("ldapsearch failed: %s", out)
	}
	if !strings.Contains(string(out), "numEntries: 1") {
		t.Errorf("ldapsearch sizelimit 1 with filter failed - wrong number of entries: %s", out)
	}

	cmd = exec.CommandContext(ctx, "ldapsearch", "-H", "ldap://"+addr.String(), "-x",
		"-b", serverBaseDN, "-D", "cn=testy,"+serverBaseDN, "-w", "iLike2test", "-z", "0", "(uid=trent)")
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ldapsearch failed: %v", err)
	}
	if !strings.Contains(string(out), "result: 0 Success") {
		t.Errorf("ldapsearch failed: %s", out)
	}
	if !strings.Contains(string(out), "numEntries: 1") {
		t.Errorf("ldapsearch sizelimit 0 with filter failed - wrong number of entries: %s", out)
	}
}

func TestBindSearchMulti(t *testing.T) {
	s := NewServer()
	s.BindFunc("", bindSimple{})
	s.BindFunc("c=testz", bindSimple2{})
	s.SearchFunc("", searchSimple{})
	s.SearchFunc("c=testz", searchSimple2{})

	addr, err := ListenAndServe(t, s)
	if err != nil {
		t.Fatalf("Failed to listen")
	}
	t.Cleanup(s.Close)
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ldapsearch", "-H", "ldap://"+addr.String(), "-x", "-b", serverBaseDN,
		"-D", "cn=testy,o=testers,c=test", "-w", "iLike2test", "cn=ned")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ldapsearch failed: %v", err)
	}
	if !strings.Contains(string(out), "result: 0 Success") {
		t.Errorf("error routing default bind/search functions: %s", out)
	}
	if !strings.Contains(string(out), "dn: cn=ned,o=testers,c=test") {
		t.Errorf("search default routing failed: %s", out)
	}
	cmd = exec.CommandContext(ctx, "ldapsearch", "-H", "ldap://"+addr.String(), "-x", "-b", "o=testers,c=testz",
		"-D", "cn=testy,o=testers,c=testz", "-w", "ZLike2test", "cn=hamburger")
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ldapsearch failed: %v", err)
	}
	if !strings.Contains(string(out), "result: 0 Success") {
		t.Errorf("error routing custom bind/search functions: %s", out)
	}
	if !strings.Contains(string(out), "dn: cn=hamburger,o=testers,c=testz") {
		t.Errorf("search custom routing failed: %s", out)
	}
}

func TestSearchPanic(t *testing.T) {
	previousOutput := log.Writer()
	log.SetOutput(t.Output())

	t.Cleanup(func() { log.SetOutput(previousOutput) })

	s := NewServer()
	s.SearchFunc("", searchPanic{})
	s.BindFunc("", bindAnonOK{})

	addr, err := ListenAndServe(t, s)
	if err != nil {
		t.Fatalf("Failed to listen")
	}
	t.Cleanup(s.Close)
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ldapsearch", "-H", "ldap://"+addr.String(), "-x", "-b", serverBaseDN)
	out, _ := cmd.CombinedOutput()
	if !strings.Contains(string(out), "result: 80 Other (e.g., implementation specific) error") {
		t.Errorf("ldapsearch should have returned Other error due to panic: %s", out)
	}
}

type compileSearchFilterTest struct {
	name         string
	filterStr    string
	numResponses string
}

var searchFilterTestFilters = []compileSearchFilterTest{
	{name: "equalityOk", filterStr: "(uid=ned)", numResponses: "2"},
	{name: "equalityNo", filterStr: "(uid=foo)", numResponses: "1"},
	{name: "equalityOk", filterStr: "(objectclass=posixaccount)", numResponses: "4"},
	{name: "presentEmptyOk", filterStr: "", numResponses: "4"},
	{name: "presentOk", filterStr: "(objectclass=*)", numResponses: "4"},
	{name: "presentOk", filterStr: "(description=*)", numResponses: "3"},
	{name: "presentNo", filterStr: "(foo=*)", numResponses: "1"},
	{name: "andOk", filterStr: "(&(uid=ned)(objectclass=posixaccount))", numResponses: "2"},
	{name: "andNo", filterStr: "(&(uid=ned)(objectclass=posixgroup))", numResponses: "1"},
	{name: "andNo", filterStr: "(&(uid=ned)(uid=trent))", numResponses: "1"},
	{name: "orOk", filterStr: "(|(uid=ned)(uid=trent))", numResponses: "3"},
	{name: "orOk", filterStr: "(|(uid=ned)(objectclass=posixaccount))", numResponses: "4"},
	{name: "orNo", filterStr: "(|(uid=foo)(objectclass=foo))", numResponses: "1"},
	{name: "andOrOk", filterStr: "(&(|(uid=ned)(uid=trent))(objectclass=posixaccount))", numResponses: "3"},
	{name: "notOk", filterStr: "(!(uid=ned))", numResponses: "3"},
	{name: "notOk", filterStr: "(!(uid=foo))", numResponses: "4"},
	{name: "notAndOrOk", filterStr: "(&(|(uid=ned)(uid=trent))(!(objectclass=posixgroup)))", numResponses: "3"},
	{name: "Suffix", filterStr: "(objectClass=posix*)", numResponses: "4"},
	{name: "Prefix", filterStr: "(cn=*nt)", numResponses: "2"},
	{name: "Any", filterStr: "(cn=*e*)", numResponses: "3"},

	// TODO: These are not implemented
	// {name: "Greater or Equal",filterStr: "(sn>=Miller)", numResponses: "3"},
	// {name: "Less or Equal",filterStr: "(sn<=Miller)", numResponses: "3"},
	// {name: "Approximate Match",filterStr: "(sn~=Miller)", numResponses: "3"},

}

func TestSearchFiltering(t *testing.T) {
	s := NewServer()
	s.EnforceLDAP = true
	s.SearchFunc("", searchSimple{})
	s.BindFunc("", bindSimple{})

	addr, err := ListenAndServe(t, s)
	if err != nil {
		t.Fatalf("Failed to listen: %s", err)
	}
	t.Cleanup(s.Close)

	for _, i := range searchFilterTestFilters {
		cap_i := i
		t.Run(i.name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(t.Context(), timeout)
			defer cancel()
			cmd := exec.CommandContext(ctx, "ldapsearch", "-d", "99", "-H", "ldap://"+addr.String(), "-x",
				"-b", serverBaseDN, "-D", "cn=testy,"+serverBaseDN, "-w", "iLike2test", cap_i.filterStr)
			out, _ := cmd.CombinedOutput()
			if !strings.Contains(string(out), "numResponses: "+cap_i.numResponses) {
				t.Errorf("ldapsearch failed - expected numResponses==%s: %v", cap_i.numResponses, string(out))
			}
		})
	}
}

func TestSearchAttributes(t *testing.T) {
	s := NewServer()
	s.EnforceLDAP = true
	s.SearchFunc("", searchSimple{})
	s.BindFunc("", bindSimple{})

	addr, err := ListenAndServe(t, s)
	if err != nil {
		t.Fatalf("Failed to listen: %s", err)
	}
	t.Cleanup(s.Close)
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()

	filterString := ""
	cmd := exec.CommandContext(ctx, "ldapsearch", "-H", "ldap://"+addr.String(), "-x",
		"-b", serverBaseDN, "-D", "cn=testy,"+serverBaseDN, "-w", "iLike2test", filterString, "cn")
	out, _ := cmd.CombinedOutput()

	if !strings.Contains(string(out), "dn: cn=ned,o=testers,c=test") {
		t.Errorf("ldapsearch failed - missing requested DN attribute: %s", out)
	}
	if !strings.Contains(string(out), "cn: ned") {
		t.Errorf("ldapsearch failed - missing requested CN attribute: %s", out)
	}
	if strings.Contains(string(out), "uidNumber") {
		t.Errorf("ldapsearch failed - uidNumber attr should not be displayed: %s", out)
	}
	if strings.Contains(string(out), "accountstatus") {
		t.Errorf("ldapsearch failed - accountstatus attr should not be displayed: %s", out)
	}
}

func TestSearchAllUserAttributes(t *testing.T) {
	s := NewServer()
	s.EnforceLDAP = true
	s.SearchFunc("", searchSimple{})
	s.BindFunc("", bindSimple{})

	addr, err := ListenAndServe(t, s)
	if err != nil {
		t.Fatalf("Failed to listen: %s", err)
	}
	t.Cleanup(s.Close)
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()

	filterString := ""
	cmd := exec.CommandContext(ctx, "ldapsearch", "-H", "ldap://"+addr.String(), "-x",
		"-b", serverBaseDN, "-D", "cn=testy,"+serverBaseDN, "-w", "iLike2test", filterString, "*")
	out, _ := cmd.CombinedOutput()

	if !strings.Contains(string(out), "dn: cn=ned,o=testers,c=test") {
		t.Errorf("ldapsearch failed - missing requested DN attribute: %s", out)
	}
	if !strings.Contains(string(out), "cn: ned") {
		t.Errorf("ldapsearch failed - missing requested CN attribute: %s", out)
	}
	if !strings.Contains(string(out), "uidNumber") {
		t.Errorf("ldapsearch failed - missing requested uidNumber attribute: %s", out)
	}
	if !strings.Contains(string(out), "accountstatus") {
		t.Errorf("ldapsearch failed - missing requested accountstatus attribute: %s", out)
	}
	if !strings.Contains(string(out), "o: ate") {
		t.Errorf("ldapsearch failed - missing requested o attribute: %s", out)
	}
	if !strings.Contains(string(out), "description") {
		t.Errorf("ldapsearch failed - missing requested description attribute: %s", out)
	}
	if !strings.Contains(string(out), "objectclass") {
		t.Errorf("ldapsearch failed - missing requested objectclass attribute: %s", out)
	}
}

func TestSearchScope(t *testing.T) {
	s := NewServer()
	s.EnforceLDAP = true
	s.SearchFunc("", searchSimple{})
	s.BindFunc("", bindSimple{})

	addr, err := ListenAndServe(t, s)
	if err != nil {
		t.Fatalf("Failed to listen: %s", err)
	}
	t.Cleanup(s.Close)
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ldapsearch", "-H", "ldap://"+addr.String(), "-x",
		"-b", "c=test", "-D", "cn=testy,o=testers,c=test", "-w", "iLike2test", "-s", "sub", "cn=trent")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ldapsearch failed: %v", err)
	}
	if !strings.Contains(string(out), "dn: cn=trent,o=testers,c=test") {
		t.Errorf("ldapsearch 'sub' scope failed - didn't find expected DN: %s", out)
	}

	cmd = exec.CommandContext(ctx, "ldapsearch", "-H", "ldap://"+addr.String(), "-x",
		"-b", serverBaseDN, "-D", "cn=testy,o=testers,c=test", "-w", "iLike2test", "-s", "one", "cn=trent")
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ldapsearch failed: %v", err)
	}
	if !strings.Contains(string(out), "dn: cn=trent,o=testers,c=test") {
		t.Errorf("ldapsearch 'one' scope failed - didn't find expected DN: %s", out)
	}
	cmd = exec.CommandContext(ctx, "ldapsearch", "-H", "ldap://"+addr.String(), "-x",
		"-b", "c=test", "-D", "cn=testy,o=testers,c=test", "-w", "iLike2test", "-s", "one", "cn=trent")
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ldapsearch failed: %v", err)
	}
	if strings.Contains(string(out), "dn: cn=trent,o=testers,c=test") {
		t.Errorf("ldapsearch 'one' scope failed - found unexpected DN: %s", out)
	}

	cmd = exec.CommandContext(ctx, "ldapsearch", "-H", "ldap://"+addr.String(), "-x",
		"-b", "cn=trent,o=testers,c=test", "-D", "cn=testy,o=testers,c=test", "-w", "iLike2test", "-s", "base", "cn=trent")
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ldapsearch failed: %v", err)
	}
	if !strings.Contains(string(out), "dn: cn=trent,o=testers,c=test") {
		t.Errorf("ldapsearch 'base' scope failed - didn't find expected DN: %s", out)
	}
	cmd = exec.CommandContext(ctx, "ldapsearch", "-H", "ldap://"+addr.String(), "-x",
		"-b", serverBaseDN, "-D", "cn=testy,o=testers,c=test", "-w", "iLike2test", "-s", "base", "cn=trent")
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ldapsearch failed: %v", err)
	}
	if strings.Contains(string(out), "dn: cn=trent,o=testers,c=test") {
		t.Errorf("ldapsearch 'base' scope failed - found unexpected DN: %s", out)
	}
}

func TestSearchScopeCaseInsensitive(t *testing.T) {
	s := NewServer()
	s.EnforceLDAP = true
	s.SearchFunc("", searchCaseInsensitive{})
	s.BindFunc("", bindCaseInsensitive{})

	addr, err := ListenAndServe(t, s)
	if err != nil {
		t.Fatalf("Failed to listen: %s", err)
	}
	t.Cleanup(s.Close)
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ldapsearch", "-H", "ldap://"+addr.String(), "-x",
		"-b", "cn=Case,o=testers,c=test", "-D", "cn=CAse,o=testers,c=test", "-w", "iLike2test", "-s", "base", "cn=CASe")
	out, _ := cmd.CombinedOutput()
	if !strings.Contains(string(out), "dn: cn=CASE,o=testers,c=test") {
		t.Errorf("ldapsearch 'base' scope failed - didn't find expected DN: %s", out)
	}
}

func TestSearchControls(t *testing.T) {
	s := NewServer()
	s.SearchFunc("", searchControls{})
	s.BindFunc("", bindSimple{})

	addr, err := ListenAndServe(t, s)
	if err != nil {
		t.Errorf("Failed to listen: %s", err)
		return
	}
	t.Cleanup(s.Close)
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ldapsearch", "-H", "ldap://"+addr.String(), "-x",
		"-b", serverBaseDN, "-D", "cn=testy,"+serverBaseDN, "-w", "iLike2test", "-e", "1.2.3.4.5")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ldapsearch failed: %v", err)
	}
	if !strings.Contains(string(out), "dn: cn=hamburger,o=testers,c=testz") {
		t.Errorf("ldapsearch with control failed: %s", out)
	}
	if !strings.Contains(string(out), "result: 0 Success") {
		t.Errorf("ldapsearch with control failed: %s", out)
	}
	if !strings.Contains(string(out), "numResponses: 2") {
		t.Errorf("ldapsearch with control failed: %s", out)
	}

	cmd = exec.CommandContext(ctx, "ldapsearch", "-H", "ldap://"+addr.String(), "-x",
		"-b", serverBaseDN, "-D", "cn=testy,"+serverBaseDN, "-w", "iLike2test")
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ldapsearch failed: %v", err)
	}
	if strings.Contains(string(out), "dn: cn=hamburger,o=testers,c=testz") {
		t.Errorf("ldapsearch without control failed: %s", out)
	}
	if !strings.Contains(string(out), "result: 0 Success") {
		t.Errorf("ldapsearch without control failed: %s", out)
	}
	if !strings.Contains(string(out), "numResponses: 1") {
		t.Errorf("ldapsearch without control failed: %s", out)
	}
}
