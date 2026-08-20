package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunRejectsInvalidArguments(t *testing.T) {
	tests := [][]string{
		{},
		{"-4", "-6", "example.com"},
		{"--format", "xml", "example.com"},
		{"--count", "0", "example.com"},
		{"example.com:99999"},
	}
	for _, args := range tests {
		var stdout, stderr bytes.Buffer
		if code := run(args, &stdout, &stderr); code != 2 {
			t.Fatalf("run(%v) code=%d stderr=%q", args, code, stderr.String())
		}
	}
}

func TestVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--version"}, &stdout, &stderr); code != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), version) {
		t.Fatalf("version output=%q", stdout.String())
	}
}

func TestHelpIsSuccessfulAndUsesStdout(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--help"}, &stdout, &stderr); code != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "usage:") || stderr.Len() != 0 {
		t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}
