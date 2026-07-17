package tui

import (
	"testing"
)

func TestValidateSSHPort(t *testing.T) {
	tests := []struct {
		input   string
		want    int
		wantErr bool
	}{
		{"", 0, false},
		{"22", 22, false},
		{"65535", 65535, false},
		{"1", 1, false},
		{"0", 0, true},
		{"-1", 0, true},
		{"65536", 0, true},
		{"abc", 0, true},
		{"22.5", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := validateSSHPort(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateSSHPort(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("validateSSHPort(%q) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsSSHTunnelFieldVisible(t *testing.T) {
	SSHTunnelEnabled = false
	if isSSHTunnelFieldVisible() {
		t.Error("expected false when SSHTunnelEnabled=false")
	}
	SSHTunnelEnabled = true
	if !isSSHTunnelFieldVisible() {
		t.Error("expected true when SSHTunnelEnabled=true")
	}
	SSHTunnelEnabled = false // restore
}

func TestSetupTimeFormat(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "EU format",
			input:    "eu",
			expected: "02/01/2006 15:04:05",
		},
		{
			name:     "Empty string",
			input:    "",
			expected: "02/01/2006 15:04:05",
		},
		{
			name:     "US format",
			input:    "US",
			expected: "01/02/2006 15:04:05",
		},
		{
			name:     "ISO format",
			input:    "ISO8601",
			expected: "2006-01-02 15:04:05",
		},
		{
			name:     "Custom format",
			input:    "20060102150405",
			expected: "20060102150405",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := setupTimeFormat(tt.input)
			if result != tt.expected {
				t.Errorf("got %q, want %q", result, tt.expected)
			}
		})
	}
}
