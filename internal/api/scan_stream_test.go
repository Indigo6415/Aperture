package api

import "testing"

// TestScanRate checks the default, the accepted range, and the rejected
// values for a requested scan speed.
func TestScanRate(t *testing.T) {
	cases := []struct {
		name      string
		requested float64
		want      float64
		wantErr   bool
	}{
		{name: "omitted uses default", requested: 0, want: defaultScanRPS},
		{name: "slow", requested: 10, want: 10},
		{name: "fractional custom", requested: 0.5, want: 0.5},
		{name: "at cap", requested: maxScanRPS, want: maxScanRPS},
		{name: "negative rejected", requested: -1, wantErr: true},
		{name: "above cap rejected", requested: maxScanRPS + 1, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := scanRate(tc.requested)
			if (err != nil) != tc.wantErr {
				t.Fatalf("scanRate(%v) error = %v, wantErr %v", tc.requested, err, tc.wantErr)
			}
			if got != tc.want {
				t.Fatalf("scanRate(%v) = %v, want %v", tc.requested, got, tc.want)
			}
		})
	}
}
