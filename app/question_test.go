package main

import (
	"encoding/binary"
	"testing"
)

func TestParseQuestionsWithCompressedDomainName(t *testing.T) {
	data := make([]byte, 12)
	header := DNSHeader{QDCount: 2}

	firstQuestion := (&DNSQuestion{
		Name:  "abc.def.example.com",
		Type:  1,
		Class: 1,
	}).ToBytes()
	data = append(data, firstQuestion...)

	suffixOffset := 12 + len([]byte{3, 'a', 'b', 'c', 3, 'd', 'e', 'f'})
	data = append(data, 3, 'a', 'b', 'c', 3, 'd', 'e', 'f')
	data = append(data, 0xC0, byte(suffixOffset)) // Pointer to "example.com" in the first question.
	data = binary.BigEndian.AppendUint16(data, 1)
	data = binary.BigEndian.AppendUint16(data, 1)

	questions, nextOffset, err := ParseQuestions(data, header, 12)
	if err != nil {
		t.Fatalf("ParseQuestions returned error: %v", err)
	}

	if nextOffset != len(data) {
		t.Fatalf("next offset = %d, want %d", nextOffset, len(data))
	}
	if questions[0].Name != "abc.def.example.com" {
		t.Fatalf("first question name = %q", questions[0].Name)
	}
	if questions[1].Name != "abc.def.example.com" {
		t.Fatalf("second question name = %q", questions[1].Name)
	}
}
