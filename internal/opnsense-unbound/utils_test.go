package opnsense

import (
	"encoding/json"
	"testing"

	"sigs.k8s.io/external-dns/endpoint"
)

func TestApplyAddPtrToRecord(t *testing.T) {
	t.Parallel()
	newA := func() *endpoint.Endpoint {
		return endpoint.NewEndpoint("foo.bar.com", "A", "192.168.99.216")
	}

	var rec DNSRecord
	ApplyAddPtrToRecord(&rec, newA())
	if rec.AddPtr != "" {
		t.Errorf("no providerSpecific: want AddPtr omitted (empty), got %q", rec.AddPtr)
	}

	rec = DNSRecord{}
	ep := newA()
	ep.SetProviderSpecificProperty(ProviderSpecificAddPtrKey, "0")
	ApplyAddPtrToRecord(&rec, ep)
	if rec.AddPtr != "0" {
		t.Errorf("explicit 0: want 0, got %q", rec.AddPtr)
	}

	rec = DNSRecord{}
	ep1 := newA()
	ep1.SetProviderSpecificProperty(ProviderSpecificAddPtrKey, "1")
	ApplyAddPtrToRecord(&rec, ep1)
	if rec.AddPtr != "1" {
		t.Errorf("explicit 1: want 1, got %q", rec.AddPtr)
	}

	rec = DNSRecord{}
	epTxt := endpoint.NewEndpoint("foo.bar.com", "TXT", "text")
	epTxt.SetProviderSpecificProperty(ProviderSpecificAddPtrKey, "1")
	ApplyAddPtrToRecord(&rec, epTxt)
	if rec.AddPtr != "" {
		t.Errorf("TXT: opnsense/addptr ignored, want AddPtr empty, got %q", rec.AddPtr)
	}

	rec = DNSRecord{}
	epAAAA := endpoint.NewEndpoint("foo.bar.com", "AAAA", "2001:db8::1")
	epAAAA.SetProviderSpecificProperty(ProviderSpecificAddPtrKey, "0")
	ApplyAddPtrToRecord(&rec, epAAAA)
	if rec.AddPtr != "0" {
		t.Errorf("AAAA explicit 0: want 0, got %q", rec.AddPtr)
	}
}

func TestDNSRecordJSONIncludesAddptrWhenSet(t *testing.T) {
	t.Parallel()
	body, err := json.Marshal(unboundAddHostOverride{
		Host: DNSRecord{
			Enabled:  "1",
			Rr:       "A",
			Hostname: "app",
			Domain:   "example.com",
			Server:   "10.0.0.1",
			AddPtr:   "0",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatal(err)
	}
	host, ok := m["host"].(map[string]any)
	if !ok {
		t.Fatalf("host: %#v", m["host"])
	}
	if host["addptr"] != "0" {
		t.Fatalf("addptr: want \"0\", got %#v", host["addptr"])
	}
}

func TestDNSRecordJSONOmitsAddptrWhenEmpty(t *testing.T) {
	t.Parallel()
	body, err := json.Marshal(unboundAddHostOverride{
		Host: DNSRecord{
			Enabled:  "1",
			Rr:       "A",
			Hostname: "app",
			Domain:   "example.com",
			Server:   "10.0.0.1",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatal(err)
	}
	host, ok := m["host"].(map[string]any)
	if !ok {
		t.Fatalf("host: %#v", m["host"])
	}
	if _, has := host["addptr"]; has {
		t.Fatalf("addptr should be omitted, host=%#v", host)
	}
}
