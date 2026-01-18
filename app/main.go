package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
)

// DNSHeader represents a DNS packet header with bit-level fields
type DNSHeader struct {
	ID      uint16 // 16 bits - Packet Identifier
	Flags   uint16 // 16 bits - Contains QR, OPCODE, AA, TC, RD, RA, Z, RCODE
	QDCount uint16 // 16 bits - Question Count
	ANCount uint16 // 16 bits - Answer Record Count
	NSCount uint16 // 16 bits - Authority Record Count
	ARCount uint16 // 16 bits - Additional Record Count
}

type DNSQuestion struct {
	Name  string // Domain name being queried
	Type  uint16 // 16 bits - Question Type (e.g., 1 for A record, 28 for AAAA)
	Class uint16 // 16 bits - Question Class (e.g., 1 for IN - Internet)
}

// ToBytes converts a question to DNS format
func (q *DNSQuestion) ToBytes() []byte {
	var buf []byte

	// Add domain name
	buf = append(buf, encodeDomainName(q.Name)...)

	// Add Type and Class
	typeBytes := make([]byte, 2)
	classBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(typeBytes, q.Type)
	binary.BigEndian.PutUint16(classBytes, q.Class)
	buf = append(buf, typeBytes...)
	buf = append(buf, classBytes...)

	return buf
}

// Bit masks for extracting/setting individual flag bits
const (
	// Position in the Flags field (bits are counted from left/msb)
	QRMask     = 0x8000 // Bit 15: Query/Response Indicator
	OPCODEMask = 0x7800 // Bits 11-14: Operation Code (4 bits)
	AAMask     = 0x0400 // Bit 10: Authoritative Answer
	TCMask     = 0x0200 // Bit 9: Truncation
	RDMask     = 0x0100 // Bit 8: Recursion Desired
	RAMask     = 0x0080 // Bit 7: Recursion Available
	ZMask      = 0x0070 // Bits 4-6: Reserved (Z) (3 bits)
	RCODEMask  = 0x000F // Bits 0-3: Response Code (4 bits)
)

func (h *DNSHeader) SetQR(qr byte) {
	h.Flags = (h.Flags & ^uint16(QRMask)) | (uint16(qr) << 15)
}

func (h *DNSHeader) GetQR() byte {
	return byte((h.Flags & uint16(QRMask)) >> 15)
}

func (h *DNSHeader) SetOPCODE(opcode byte) {
	h.Flags = (h.Flags & ^uint16(OPCODEMask)) | (uint16(opcode) << 11)
}

func (h *DNSHeader) GetOPCODE() byte {
	return byte((h.Flags & uint16(OPCODEMask)) >> 11)
}

func (h *DNSHeader) SetAA(aa byte) {
	h.Flags = (h.Flags & ^uint16(AAMask)) | (uint16(aa) << 10)
}

func (h *DNSHeader) GetAA() byte {
	return byte((h.Flags & uint16(AAMask)) >> 10)
}

func (h *DNSHeader) SetTC(tc byte) {
	h.Flags = (h.Flags & ^uint16(TCMask)) | (uint16(tc) << 9)
}

func (h *DNSHeader) GetTC() byte {
	return byte((h.Flags & uint16(TCMask)) >> 9)
}

func (h *DNSHeader) SetRD(rd byte) {
	h.Flags = (h.Flags & ^uint16(RDMask)) | (uint16(rd) << 8)
}

func (h *DNSHeader) GetRD() byte {
	return byte((h.Flags & uint16(RDMask)) >> 8)
}

func (h *DNSHeader) SetRA(ra byte) {
	h.Flags = (h.Flags & ^uint16(RAMask)) | (uint16(ra) << 7)
}

func (h *DNSHeader) GetRA() byte {
	return byte((h.Flags & uint16(RAMask)) >> 7)
}

func (h *DNSHeader) SetZ(z byte) {
	h.Flags = (h.Flags & ^uint16(ZMask)) | (uint16(z) << 6)
}

func (h *DNSHeader) GetZ() byte {
	return byte((h.Flags & ZMask) >> 4)
}

func (h *DNSHeader) SetRCODE(rcode byte) {
	h.Flags = (h.Flags & ^uint16(RCODEMask)) | uint16(rcode&0x0F)
}

func (h *DNSHeader) GetRCODE() byte {
	return byte(h.Flags & RCODEMask)
}

// CreateResponseHeader creates a DNS response header with expected values
func CreateResponseHeader(queryID uint16) DNSHeader {
	header := DNSHeader{
		ID:      queryID, // Should match the query ID (1234 in your case)
		QDCount: 0,
		ANCount: 0,
		NSCount: 0,
		ARCount: 0,
	}

	// Set all flags according to expected values
	header.SetQR(1)     // 1 for response
	header.SetOPCODE(0) // Standard query
	header.SetAA(0)     // Non-authoritative
	header.SetTC(0)     // Not truncated
	header.SetRD(0)     // Recursion not desired
	header.SetRA(0)     // Recursion not available
	header.SetZ(0)      // Reserved bits = 0
	header.SetRCODE(0)  // No error

	return header
}

// ToBytes converts the header to network byte order (big-endian)
func (h *DNSHeader) ToBytes() []byte {
	data := make([]byte, 12) // DNS header is always 12 bytes
	binary.BigEndian.PutUint16(data[0:2], h.ID)
	binary.BigEndian.PutUint16(data[2:4], h.Flags)
	binary.BigEndian.PutUint16(data[4:6], h.QDCount)
	binary.BigEndian.PutUint16(data[6:8], h.ANCount)
	binary.BigEndian.PutUint16(data[8:10], h.NSCount)
	binary.BigEndian.PutUint16(data[10:12], h.ARCount)
	return data
}

// ParseHeader parses a DNS header from bytes
func ParseHeader(data []byte) (DNSHeader, error) {
	if len(data) < 12 {
		return DNSHeader{}, ErrInvalidHeader
	}

	return DNSHeader{
		ID:      binary.BigEndian.Uint16(data[0:2]),
		Flags:   binary.BigEndian.Uint16(data[2:4]),
		QDCount: binary.BigEndian.Uint16(data[4:6]),
		ANCount: binary.BigEndian.Uint16(data[6:8]),
		NSCount: binary.BigEndian.Uint16(data[8:10]),
		ARCount: binary.BigEndian.Uint16(data[10:12]),
	}, nil
}

var ErrInvalidHeader = errors.New("invalid DNS header")

// parseDomainName parses a domain name from DNS data
func parseDomainName(data []byte, offset int) (string, int, error) {
	var labels []string
	start := offset

	for {
		if offset >= len(data) {
			return "", start, errors.New("domain name exceeds buffer")
		}

		// Read label length
		labelLength := int(data[offset])
		offset++ // Move past the label length byte

		// Flush byte, end of domain name
		if labelLength == 0 {
			break
		}

		if offset+labelLength > len(data) {
			return "", start, errors.New("label length exceeds buffer")
		}

		// Read the label
		label := string(data[offset : offset+labelLength])
		labels = append(labels, label)

		// Move pass the label
		offset += labelLength
	}

	// Join the labels with dots to form the domain name
	domain := ""
	for _, label := range labels {
		domain += label + "."
	}
	// Remove the trailing dot
	domain = domain[:len(domain)-1]

	return domain, offset, nil
}

// ParseQuestions reads DNS Question
func ParseQuestions(data []byte, header DNSHeader, offset int) ([]DNSQuestion, int, error) {
	questions := make([]DNSQuestion, header.QDCount)

	for i := 0; i < int(header.QDCount); i++ {
		// Parse domain name
		name, newOffset, err := parseDomainName(data, offset)
		if err != nil {
			return nil, 0, err
		}
		offset = newOffset

		// Check if we have enough bytes for Type and Class
		if offset+4 > len(data) {
			return nil, 0, errors.New("malformed DNS question: insufficient data for QTYPE and QCLASS")
		}

		// Read Type (2 bytes) and Class(2 bytes)
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

	// Split domain name into labels
	labels := strings.Split(domain, ".")

	// Encode each lavel
	for _, label := range labels {
		buf = append(buf, byte(len(label)))
		buf = append(buf, []byte(label)...)
	}

	// Add terminating null byte
	buf = append(buf, 0x00)

	return buf
}

// QuestionToBytes converts multiple questions to DNS format
func QuestionsToBytes(questions []DNSQuestion) []byte {
	var buf []byte
	for _, q := range questions {
		buf = append(buf, q.ToBytes()...)
	}
	return buf
}

// HandleDNSQuery processes a DNS query
func HandleDNSQuery(data []byte) ([]byte, error) {
	// Parse DNS Header
	if len(data) < 12 {
		return nil, errors.New("packet too short for DNS header")
	}

	header, err := ParseHeader(data[:12])
	if err != nil {
		return nil, err
	}

	// Parse questions from client query
	questions, _, err := ParseQuestions(data, header, 12)
	if err != nil {
		return nil, err
	}

	// Log questions
	for i, q := range questions {
		fmt.Printf("Question %d: %s (Type: %d, Class: %d)\n",
			i+1, q.Name, q.Type, q.Class)
	}

	// Create response header
	responseHeader := CreateResponseHeader(header.ID)
	responseHeader.QDCount = header.QDCount

	// Build response
	var response []byte

	// 1. Add header
	response = append(response, responseHeader.ToBytes()...)

	// 2. Echo back the questions
	response = append(response, QuestionsToBytes(questions)...)

	return response, nil
}

func main() {
	// You can use print statements as follows for debugging, they'll be visible when running tests.
	fmt.Println("Logs from your program will appear here!")

	// TODO: Uncomment the code below to pass the first stage

	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:2053")
	if err != nil {
		fmt.Println("Failed to resolve UDP address:", err)
		return
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		fmt.Println("Failed to bind to address:", err)
		return
	}
	defer udpConn.Close()

	buf := make([]byte, 512)

	for {
		size, source, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Error receiving data:", err)
			break
		}

		receivedData := string(buf[:size])
		fmt.Printf("Received %d bytes from %s: %s\n", size, source, receivedData)

		response, err := HandleDNSQuery(buf[:size])

		_, err = udpConn.WriteToUDP(response, source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}
