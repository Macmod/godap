package main

import (
	"testing"
)

func TestSetupTimeFormat(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "EU format",
			input:    "EU",
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
			input:    "ISO",
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
