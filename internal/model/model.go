package model

import "time"

const SchemaVersion = "1"

type Status string

const (
	StatusOK       Status = "ok"
	StatusWarn     Status = "warn"
	StatusFail     Status = "fail"
	StatusDegraded Status = "degraded"
	StatusSkipped  Status = "skipped"
)

type Target struct {
	Input      string   `json:"input"`
	Host       string   `json:"host"`
	Port       int      `json:"port"`
	ServerName string   `json:"server_name,omitempty"`
	Addresses  []string `json:"addresses,omitempty"`
	IP         string   `json:"ip,omitempty"`
	Family     string   `json:"family,omitempty"`
}

type DNSResult struct {
	Status   Status   `json:"status"`
	Host     string   `json:"host"`
	IPs      []string `json:"ips,omitempty"`
	Selected string   `json:"selected,omitempty"`
	Family   string   `json:"family,omitempty"`
	Elapsed  int64    `json:"elapsed_ms"`
	Error    string   `json:"error,omitempty"`
}

type PingSample struct {
	Sequence int      `json:"sequence"`
	Status   Status   `json:"status"`
	RTTMs    *float64 `json:"rtt_ms"`
	Error    string   `json:"error,omitempty"`
}

type PingResult struct {
	Status    Status       `json:"status"`
	Backend   string       `json:"backend"`
	Degraded  bool         `json:"degraded"`
	Sent      int          `json:"sent"`
	Received  int          `json:"received"`
	LossPct   float64      `json:"loss_pct"`
	MinMs     *float64     `json:"min_ms"`
	AvgMs     *float64     `json:"avg_ms"`
	MaxMs     *float64     `json:"max_ms"`
	Samples   []PingSample `json:"samples"`
	ErrorKind string       `json:"error_kind,omitempty"`
	Error     string       `json:"error,omitempty"`
}

type TraceProbe struct {
	Status    Status   `json:"status"`
	Responder string   `json:"responder,omitempty"`
	RTTMs     *float64 `json:"rtt_ms"`
	Note      string   `json:"note,omitempty"`
}

type TraceHop struct {
	TTL    int          `json:"ttl"`
	Probes []TraceProbe `json:"probes"`
}

type TraceResult struct {
	Status    Status     `json:"status"`
	Backend   string     `json:"backend"`
	Degraded  bool       `json:"degraded"`
	Hops      []TraceHop `json:"hops"`
	ErrorKind string     `json:"error_kind,omitempty"`
	Error     string     `json:"error,omitempty"`
}

type TCPResult struct {
	Status  Status `json:"status"`
	Address string `json:"address"`
	Elapsed int64  `json:"elapsed_ms"`
	Error   string `json:"error,omitempty"`
}

type TLSResult struct {
	Status      Status `json:"status"`
	Version     string `json:"version,omitempty"`
	CipherSuite string `json:"cipher_suite,omitempty"`
	ALPN        string `json:"alpn,omitempty"`
	Elapsed     int64  `json:"elapsed_ms"`
	Error       string `json:"error,omitempty"`
}

type CertificateResult struct {
	Status        Status     `json:"status"`
	Subject       string     `json:"subject,omitempty"`
	Issuer        string     `json:"issuer,omitempty"`
	SerialNumber  string     `json:"serial_number,omitempty"`
	DNSNames      []string   `json:"dns_names,omitempty"`
	NotBefore     *time.Time `json:"not_before,omitempty"`
	NotAfter      *time.Time `json:"not_after,omitempty"`
	DaysRemaining *int       `json:"days_remaining,omitempty"`
	HostnameMatch *bool      `json:"hostname_match,omitempty"`
	ChainValid    *bool      `json:"chain_valid,omitempty"`
	SHA256        string     `json:"sha256,omitempty"`
	Error         string     `json:"error,omitempty"`
}

type Summary struct {
	Status      Status   `json:"status"`
	FailedStage string   `json:"failed_stage,omitempty"`
	Warnings    []string `json:"warnings,omitempty"`
	Elapsed     int64    `json:"elapsed_ms"`
}

type Report struct {
	SchemaVersion string             `json:"schema_version"`
	Mode          string             `json:"mode"`
	Target        Target             `json:"target"`
	DNS           *DNSResult         `json:"dns,omitempty"`
	Ping          *PingResult        `json:"ping,omitempty"`
	Trace         *TraceResult       `json:"trace,omitempty"`
	TCP           *TCPResult         `json:"tcp,omitempty"`
	TLS           *TLSResult         `json:"tls,omitempty"`
	Certificate   *CertificateResult `json:"certificate,omitempty"`
	Summary       Summary            `json:"summary"`
}

type Event struct {
	SchemaVersion string             `json:"schema_version"`
	Type          string             `json:"type"`
	Mode          string             `json:"mode,omitempty"`
	Target        *Target            `json:"target,omitempty"`
	DNS           *DNSResult         `json:"dns,omitempty"`
	PingSample    *PingSample        `json:"ping_sample,omitempty"`
	Ping          *PingResult        `json:"ping,omitempty"`
	TraceHop      *TraceHop          `json:"trace_hop,omitempty"`
	Trace         *TraceResult       `json:"trace,omitempty"`
	TCP           *TCPResult         `json:"tcp,omitempty"`
	TLS           *TLSResult         `json:"tls,omitempty"`
	Certificate   *CertificateResult `json:"certificate,omitempty"`
	Summary       *Summary           `json:"summary,omitempty"`
}
