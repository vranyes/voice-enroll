package enroll

import "testing"

func TestNormalizeE164(t *testing.T) {
	cases := []struct{ in, want string }{
		{"+1 (555) 010-9999", "+15550109999"},
		{"15550109999", "+15550109999"},
		{"+15550109999", "+15550109999"},
		{"+44 20 7946 0958", "+442079460958"},
		{"  +1 (555) 010-9999  ", "+15550109999"},
	}
	for _, c := range cases {
		got, err := NormalizeE164(c.in)
		if err != nil {
			t.Fatalf("NormalizeE164(%q) error: %v", c.in, err)
		}
		if got != c.want {
			t.Fatalf("NormalizeE164(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestNormalizeE164Rejects(t *testing.T) {
	for _, in := range []string{"", "abc", "123456", "+1234567890123456", "call me"} {
		if _, err := NormalizeE164(in); err == nil {
			t.Fatalf("NormalizeE164(%q) accepted, want rejection", in)
		}
	}
}
