package main

import (
	"encoding/binary"
	"math/rand"
	"net"
	"time"
)

type DNSAnswer struct {
	Name   string
	Type   uint16
	Class  uint16
	TTL    uint32
	Length uint16
	Data   []byte
}

/**
 * Record
 *
 * Name	Label Sequence	The domain name encoded as a sequence of labels.
 * Type	2-byte Integer	1 for an A record, 5 for a CNAME record etc., full list here
 * Class	2-byte Integer	Usually set to 1 (full list here)
 * TTL (Time-To-Live)	4-byte Integer	The duration in seconds a record can be cached before requerying.
 * Length (RDLENGTH)	2-byte Integer	Length of the RDATA field in bytes.
 * Data (RDATA)	Variable	Data specific to the record type.
 */

// ToBytes converts an answer to DNS format
func (a *DNSAnswer) ToBytes() []byte {
	var buf []byte

	buf = append(buf, encodeDomainName(a.Name)...)

	typeBytes := make([]byte, 2)
	classBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(typeBytes, a.Type)
	binary.BigEndian.PutUint16(classBytes, a.Class)
	buf = append(buf, typeBytes...)
	buf = append(buf, classBytes...)

	ttlBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(ttlBytes, a.TTL)
	buf = append(buf, ttlBytes...)

	lengthBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(lengthBytes, a.Length)
	buf = append(buf, lengthBytes...)

	buf = append(buf, a.Data...)

	return buf
}

// CreateAnswerForQuestion gives answer to DNS questions
func CreateAnswerForQuestion(q DNSQuestion) (DNSAnswer, error) {
	// Only handle A records for now
	if q.Type != 1 {
		return DNSAnswer{}, nil
	}

	// Only handle IN class
	if q.Class != 1 {
		return DNSAnswer{}, nil
	}

	IP := generateRandomIP()

	answer := DNSAnswer{
		Name:   q.Name,
		Type:   q.Type,
		Class:  q.Class,
		TTL:    3600,
		Length: 4,
		Data:   IP.To4(),
	}

	return answer, nil
}

// generateRandomIP generates a random IP address
func generateRandomIP() net.IP {
	rand.Seed(time.Now().UnixNano())

	ip := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		ip[i] = byte(rand.Intn(223) + 1)
	}

	return ip
}
