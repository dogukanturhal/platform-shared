// SPDX-License-Identifier: Apache-2.0

package database

import (
	"net/url"
	"testing"
)

func TestBuildDSN(t *testing.T) {
	const master = "postgres://app:s3cret@db-master:5432/hexxlock_master?sslmode=require&application_name=x"
	tests := []struct {
		name     string
		master   string
		database string
		schema   string
		host     string
		port     int
		wantHost string
		wantPort string
		wantDB   string
		wantPath string // expected search_path, "" = none
	}{
		{"unchanged", master, "", "", "", 0, "db-master", "5432", "hexxlock_master", ""},
		{"hostname default port keeps master port", master, "t1", "", "db-t1", 0, "db-t1", "5432", "t1", ""},
		{"hostname and port", master, "t1", "", "db-t1", 6432, "db-t1", "6432", "t1", ""},
		{"ipv4", master, "t1", "", "10.0.0.7", 5433, "10.0.0.7", "5433", "t1", ""},
		{"host with embedded port", master, "t1", "", "db-t1:7000", 0, "db-t1", "7000", "t1", ""},
		{"explicit port beats embedded", master, "t1", "", "db-t1:7000", 6432, "db-t1", "6432", "t1", ""},
		{"ipv6 bare", master, "t1", "", "2001:db8::1", 5432, "2001:db8::1", "5432", "t1", ""},
		{"ipv6 bracketed with port", master, "t1", "", "[2001:db8::1]:5434", 0, "2001:db8::1", "5434", "t1", ""},
		{"ipv6 bare default port from master", master, "t1", "", "::1", 0, "::1", "5432", "t1", ""},
		{"schema search_path", master, "t1", "tenant_a", "", 0, "db-master", "5432", "t1", "tenant_a,public"},
		{"public schema no search_path", master, "t1", "public", "", 0, "db-master", "5432", "t1", ""},
		{"master without port, no override", "postgres://u:p@h/db", "t1", "", "", 0, "h", "", "t1", ""},
		{"special chars in password preserved", "postgres://app:p%40ss%2Fw%3Ard%23@db-master:5432/m", "t1", "", "db-t1", 6432, "db-t1", "6432", "t1", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &TenantConnectionManager{masterDSN: tt.master}
			got := m.buildDSN(tt.database, tt.schema, tt.host, tt.port)
			u, err := url.Parse(got)
			if err != nil {
				t.Fatalf("result not parseable: %q: %v", got, err)
			}
			if u.Hostname() != tt.wantHost || u.Port() != tt.wantPort {
				t.Errorf("host/port = %q/%q, want %q/%q (dsn %q)", u.Hostname(), u.Port(), tt.wantHost, tt.wantPort, got)
			}
			if u.Path != "/"+tt.wantDB {
				t.Errorf("db = %q, want %q", u.Path, tt.wantDB)
			}
			if sp := u.Query().Get("search_path"); sp != tt.wantPath {
				t.Errorf("search_path = %q, want %q", sp, tt.wantPath)
			}
			orig, _ := url.Parse(tt.master)
			if u.User.String() != orig.User.String() {
				t.Errorf("userinfo changed: %q vs %q", u.User.String(), orig.User.String())
			}
			for k, v := range orig.Query() {
				if u.Query().Get(k) != v[0] {
					t.Errorf("param %s lost: %q", k, got)
				}
			}
		})
	}
}

func TestBuildDSNKeyValue(t *testing.T) {
	m := &TenantConnectionManager{masterDSN: "host=h port=5432 user=u password='p w' dbname=m sslmode=require"}
	got := m.buildDSN("t1", "s1", "[::1]:7000", 0)
	want := "host=h port=5432 user=u password='p w' dbname=m sslmode=require dbname='t1' host='::1' port=7000 search_path='s1,public'"
	if got != want {
		t.Errorf("got %q\nwant %q", got, want)
	}
}
