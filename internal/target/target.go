package target

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/drvoss/pingcert/internal/model"
)

func Parse(input string, defaultPort int, serverName string) (model.Target, error) {
	raw := strings.TrimSpace(input)
	if raw == "" {
		return model.Target{}, fmt.Errorf("target is empty")
	}

	host := raw
	port := defaultPort
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil || u.Hostname() == "" {
			return model.Target{}, fmt.Errorf("invalid target %q", input)
		}
		if u.Scheme != "https" {
			return model.Target{}, fmt.Errorf("unsupported URL scheme %q: want https", u.Scheme)
		}
		if u.User != nil {
			return model.Target{}, fmt.Errorf("URL credentials are not supported")
		}
		host = u.Hostname()
		if p := u.Port(); p != "" {
			n, err := parsePort(p)
			if err != nil {
				return model.Target{}, err
			}
			port = n
		}
	} else if h, p, err := net.SplitHostPort(raw); err == nil {
		host = h
		n, err := parsePort(p)
		if err != nil {
			return model.Target{}, err
		}
		port = n
	} else if strings.Count(raw, ":") == 1 {
		parts := strings.SplitN(raw, ":", 2)
		if n, err := parsePort(parts[1]); err == nil {
			host, port = parts[0], n
		}
	}

	host = strings.Trim(host, "[]")
	if host == "" {
		return model.Target{}, fmt.Errorf("target host is empty")
	}
	if port < 1 || port > 65535 {
		return model.Target{}, fmt.Errorf("port must be between 1 and 65535")
	}
	if serverName == "" && net.ParseIP(host) == nil {
		serverName = host
	}
	return model.Target{
		Input:      input,
		Host:       host,
		Port:       port,
		ServerName: serverName,
	}, nil
}

func parsePort(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("invalid port %q", s)
	}
	return n, nil
}
