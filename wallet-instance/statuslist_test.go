package main

import (
	"encoding/json"
	"os"
	"strconv"
	"testing"
)

// Test vectors of draft-ietf-oauth-status-list (shared with the TypeScript tests).
func TestStatusListVectors(t *testing.T) {
	raw, err := os.ReadFile("../test/status-list-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Bits     int            `json:"bits"`
		Size     int            `json:"size"`
		Lst      string         `json:"lst"`
		Bytes    []int          `json:"bytes"`
		Statuses map[string]int `json:"statuses"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, v := range vectors {
		list, err := DecodeStatusList(v.Bits, v.Lst)
		if err != nil {
			t.Fatalf("%d-bit: %v", v.Bits, err)
		}
		if list.Size() != v.Size {
			t.Fatalf("%d-bit: size %d != %d", v.Bits, list.Size(), v.Size)
		}
		for i, b := range v.Bytes {
			if int(list.Bytes[i]) != b {
				t.Fatalf("%d-bit: byte %d = %x, want %x", v.Bits, i, list.Bytes[i], b)
			}
		}
		for i := 0; v.Statuses != nil && i < list.Size(); i++ {
			got, _ := list.Get(i)
			if want := v.Statuses[strconv.Itoa(i)]; got != want {
				t.Fatalf("%d-bit: status[%d] = %d, want %d", v.Bits, i, got, want)
			}
		}
		if _, err := list.Get(list.Size()); err == nil {
			t.Fatalf("%d-bit: out of bounds index accepted", v.Bits)
		}
	}
}
