package store

import (
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// openTestStore opens a fresh store in a temp dir and closes it on cleanup.
func openTestStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// TestPoolsUseWALAndBusyTimeout confirms the DSN pragmas actually reach the
// connections. The read pool matters most: its readers must run alongside the
// writer, which needs WAL.
func TestPoolsUseWALAndBusyTimeout(t *testing.T) {
	st := openTestStore(t)
	var mode string
	if err := st.rdb.QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil {
		t.Fatal(err)
	}
	if mode != "wal" {
		t.Errorf("read pool journal_mode = %q, want wal", mode)
	}
	var timeout int
	if err := st.rdb.QueryRow(`PRAGMA busy_timeout`).Scan(&timeout); err != nil {
		t.Fatal(err)
	}
	if timeout != 5000 {
		t.Errorf("read pool busy_timeout = %d, want 5000", timeout)
	}
	if err := st.db.QueryRow(`PRAGMA busy_timeout`).Scan(&timeout); err != nil {
		t.Fatal(err)
	}
	if timeout != 5000 {
		t.Errorf("writer busy_timeout = %d, want 5000", timeout)
	}
}

// TestCaseScopeRoundTrip checks save, read-back, de-duplication, blank
// dropping, replacement, and clearing a case's scope.
func TestCaseScopeRoundTrip(t *testing.T) {
	st := openTestStore(t)

	got, err := st.GetCaseScope("case-1")
	if err != nil || len(got) != 0 {
		t.Fatalf("fresh case scope = %v, %v; want empty", got, err)
	}

	if err := st.SetCaseScope("case-1", []string{"example.com", " ", "*.lab.test", "example.com"}); err != nil {
		t.Fatal(err)
	}
	got, _ = st.GetCaseScope("case-1")
	want := []string{"example.com", "*.lab.test"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("scope = %v, want %v", got, want)
	}

	// Scope is per case: another case must not see these rules.
	if other, _ := st.GetCaseScope("case-2"); len(other) != 0 {
		t.Fatalf("case-2 leaked scope %v", other)
	}

	if err := st.SetCaseScope("case-1", []string{"other.test"}); err != nil {
		t.Fatal(err)
	}
	got, _ = st.GetCaseScope("case-1")
	if !reflect.DeepEqual(got, []string{"other.test"}) {
		t.Fatalf("after replace scope = %v, want [other.test]", got)
	}

	if err := st.SetCaseScope("case-1", nil); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.GetCaseScope("case-1"); len(got) != 0 {
		t.Fatalf("after clear scope = %v, want empty", got)
	}
}

// TestDeleteCaseRemovesScope makes sure deleting a case also drops its scope
// rows, since the table has no cascade of its own.
func TestDeleteCaseRemovesScope(t *testing.T) {
	st := openTestStore(t)
	if err := st.CreateCase("case-del", "c", ""); err != nil {
		t.Fatal(err)
	}
	if err := st.SetCaseScope("case-del", []string{"example.com"}); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteCase("case-del"); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := st.rdb.QueryRow(`SELECT COUNT(*) FROM case_scope WHERE case_id = ?`, "case-del").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("%d case_scope rows survived DeleteCase", n)
	}
}

// TestCreateSessionPrunesExpired checks that logging in clears sessions that
// have already expired, so the table cannot grow without bound.
func TestCreateSessionPrunesExpired(t *testing.T) {
	st := openTestStore(t)
	if err := st.CreateUserWithPassword("uid-1", "a@b.test", "pw"); err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-time.Hour)
	if err := st.CreateSession("stale", "uid-1", past); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateSession("fresh", "uid-1", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := st.rdb.QueryRow(`SELECT COUNT(*) FROM sessions WHERE token = 'stale'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatal("expired session was not pruned on the next login")
	}
	if err := st.rdb.QueryRow(`SELECT COUNT(*) FROM sessions WHERE token = 'fresh'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatal("fresh session was wrongly removed")
	}
}

// TestValidIdentifier pins which strings may be spliced into SQL as names.
func TestValidIdentifier(t *testing.T) {
	for _, ok := range []string{"requests", "from_ref", "_x1"} {
		if !validIdentifier(ok) {
			t.Errorf("validIdentifier(%q) = false, want true", ok)
		}
	}
	for _, bad := range []string{"", "1abc", "a b", "x;DROP TABLE y", "a-b", "x)--"} {
		if validIdentifier(bad) {
			t.Errorf("validIdentifier(%q) = true, want false", bad)
		}
	}
}
