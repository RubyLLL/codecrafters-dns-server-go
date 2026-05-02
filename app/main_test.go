package main

import (
	"net"
	"testing"
)

func TestForwardDNSQuerySplitsMultipleQuestions(t *testing.T) {
	resolver, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket returned error: %v", err)
	}
	defer resolver.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)

		buf := make([]byte, 512)
		for i := 0; i < 2; i++ {
			n, addr, err := resolver.ReadFrom(buf)
			if err != nil {
				return
			}

			header, err := ParseHeader(buf[:n])
			if err != nil {
				return
			}
			questions, _, err := ParseQuestions(buf[:n], header, 12)
			if err != nil || len(questions) != 1 {
				return
			}

			responseHeader := CreateResponseHeader(header.ID, header.GetOPCODE(), header.GetRD())
			responseHeader.QDCount = 1
			responseHeader.ANCount = 1

			answer := DNSAnswer{
				Name:   questions[0].Name,
				Type:   questions[0].Type,
				Class:  questions[0].Class,
				TTL:    60,
				Length: 4,
				Data:   net.ParseIP("1.2.3.4").To4(),
			}

			var response []byte
			response = append(response, responseHeader.ToBytes()...)
			response = append(response, QuestionsToBytes(questions)...)
			response = append(response, answer.ToBytes()...)

			_, _ = resolver.WriteTo(response, addr)
		}
	}()

	header := DNSHeader{ID: 1234, QDCount: 2}
	header.SetRD(1)
	questions := []DNSQuestion{
		{Name: "abc.example.com", Type: 1, Class: 1},
		{Name: "def.example.com", Type: 1, Class: 1},
	}

	response, err := ForwardDNSQuery(header, questions, resolver.LocalAddr().String())
	if err != nil {
		t.Fatalf("ForwardDNSQuery returned error: %v", err)
	}

	responseHeader, err := ParseHeader(response)
	if err != nil {
		t.Fatalf("ParseHeader returned error: %v", err)
	}
	if responseHeader.QDCount != 2 {
		t.Fatalf("QDCount = %d, want 2", responseHeader.QDCount)
	}
	if responseHeader.ANCount != 2 {
		t.Fatalf("ANCount = %d, want 2", responseHeader.ANCount)
	}

	_, offset, err := ParseQuestions(response, responseHeader, 12)
	if err != nil {
		t.Fatalf("ParseQuestions returned error: %v", err)
	}
	answers, _, err := ParseAnswers(response, offset, responseHeader.ANCount)
	if err != nil {
		t.Fatalf("ParseAnswers returned error: %v", err)
	}
	if answers[0].Name != "abc.example.com" || answers[1].Name != "def.example.com" {
		t.Fatalf("answer names = %q, %q", answers[0].Name, answers[1].Name)
	}

	<-done
}
