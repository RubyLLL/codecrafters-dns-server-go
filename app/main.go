package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
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

		// Extract ID from request
		requestID := binary.BigEndian.Uint16(buf[0:2])

		// Create a response header with expected values
		header := CreateResponseHeader(requestID)

		// Convert to bytes for transimission
		response := header.ToBytes()

		_, err = udpConn.WriteToUDP(response, source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}
