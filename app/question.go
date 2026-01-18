package main

import (
	"encoding/binary"
	"errors"
	"strings"
)

type DNSQuestion struct {
	Name  string // Domain name being queried
	Type  uint16 // 16 bits - Question Type
	Class uint16 // 16 bits - Question Class
}

// ToBytes converts a question to DNS format
func (q *DNSQuestion) ToBytes() []byte {
	var buf []byte

	buf = append(buf, encodeDomainName(q.Name)...)

	typeBytes := make([]byte, 2)
	classBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(typeBytes, q.Type)
	binary.BigEndian.PutUint16(classBytes, q.Class)
	buf = append(buf, typeBytes...)
	buf = append(buf, classBytes...)

	return buf
}

// parseDomainName parses a domain name from DNS data
func parseDomainName(data []byte, offset int) (string, int, error) {
	var labels []string
	start := offset

	for {
		if offset >= len(data) {
			return "", start, errors.New("domain name exceeds buffer")
		}

		labelLength := int(data[offset])
		offset++

		if labelLength == 0 {
			break
		}

		if offset+labelLength > len(data) {
			return "", start, errors.New("label length exceeds buffer")
		}

		label := string(data[offset : offset+labelLength])
		labels = append(labels, label)
		offset += labelLength
	}

	domain := strings.Join(labels, ".")
	return domain, offset, nil
}

// ParseQuestions reads DNS Question
func ParseQuestions(data []byte, header DNSHeader, offset int) ([]DNSQuestion, int, error) {
	questions := make([]DNSQuestion, header.QDCount)

	for i := 0; i < int(header.QDCount); i++ {
		name, newOffset, err := parseDomainName(data, offset)
		if err != nil {
			return nil, 0, err
		}
		offset = newOffset

		if offset+4 > len(data) {
			return nil, 0, errors.New("malformed DNS question: insufficient data")
		}

		question := DNSQuestion{
			Name:  name,
			Type:  binary.BigEndian.Uint16(data[offset : offset+2]),
			Class: binary.BigEndian.Uint16(data[offset+2 : offset+4]),
		}
		questions[i] = question
		offset += 4
	}

	return questions, offset, nil
}

// encodeDomainName encodes a domain name to DNS format
func encodeDomainName(domain string) []byte {
	var buf []byte
	labels := strings.Split(domain, ".")

	for _, label := range labels {
		buf = append(buf, byte(len(label)))
		buf = append(buf, []byte(label)...)
	}
	buf = append(buf, 0x00)

	return buf
}

// QuestionsToBytes converts multiple questions to DNS format
func QuestionsToBytes(questions []DNSQuestion) []byte {
	var buf []byte
	for _, q := range questions {
		buf = append(buf, q.ToBytes()...)
	}
	return buf
}
