package main

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestParseAnswersWithCompressedName(t *testing.T) {
	data := make([]byte, 12)
	data = append(data, (&DNSQuestion{
		Name:  "codecrafters.io",
		Type:  1,
		Class: 1,
	}).ToBytes()...)

	answerOffset := len(data)
	data = append(data, 0xC0, 0x0C)
	data = binary.BigEndian.AppendUint16(data, 1)
	data = binary.BigEndian.AppendUint16(data, 1)
	data = binary.BigEndian.AppendUint32(data, 60)
	data = binary.BigEndian.AppendUint16(data, 4)
	data = append(data, net.ParseIP("8.8.8.8").To4()...)

	answers, nextOffset, err := ParseAnswers(data, answerOffset, 1)
	if err != nil {
		t.Fatalf("ParseAnswers returned error: %v", err)
	}

	if nextOffset != len(data) {
		t.Fatalf("next offset = %d, want %d", nextOffset, len(data))
	}
	if len(answers) != 1 {
		t.Fatalf("len(answers) = %d, want 1", len(answers))
	}
	if answers[0].Name != "codecrafters.io" {
		t.Fatalf("answer name = %q", answers[0].Name)
	}
	if got := net.IP(answers[0].Data).String(); got != "8.8.8.8" {
		t.Fatalf("answer IP = %q", got)
	}
}
