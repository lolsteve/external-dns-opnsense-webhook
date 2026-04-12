package opnsense

import (
	"strings"

	"sigs.k8s.io/external-dns/endpoint"
)

const ProviderSpecificAddPtrKey = "opnsense/addptr"

// Sets AddPtr on record for A/AAAA only when opnsense/addptr is exactly "0" or "1".
// Otherwise left blank.
func ApplyAddPtrToRecord(record *DNSRecord, ep *endpoint.Endpoint) {
	if ep.RecordType != "A" && ep.RecordType != "AAAA" {
		return
	}
	v, ok := ep.GetProviderSpecificProperty(ProviderSpecificAddPtrKey)
	if !ok {
		return
	}
	s := strings.TrimSpace(v)
	switch s {
	case "0":
		record.AddPtr = "0"
	case "1":
		record.AddPtr = "1"
	default:
		return
	}
}

// UnboundFQDNSplitter splits a DNSName into two parts,
// [0] Being the top level hostname
// [1] Being the subdomain/domain
//
// TODO: really this should return (hostname, domain string)
func SplitUnboundFQDN(hostname string) []string {
	return strings.SplitN(hostname, ".", 2)
}

func JoinUnboundFQDN(hostname string, domain string) string {
	return strings.Join([]string{hostname, domain}, ".")
}

func PruneUnboundType(unboundType string) string {
	if i := strings.IndexByte(unboundType, ' '); i != -1 {
		return unboundType[:i]
	}
	return unboundType
}

func EmbellishUnboundType(unboundType string) string {
	switch unboundType {
	case "A":
		return unboundType + " (IPv4 address)"
	case "AAAA":
		return unboundType + " (IPv6 address)"
	case "TXT":
		return unboundType + " (Text record)"
	}
	return unboundType
}
