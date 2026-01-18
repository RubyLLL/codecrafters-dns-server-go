package main

import (
	"encoding/binary"
	"errors"
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

var ErrInvalidHeader = errors.New("invalid DNS header")

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
func CreateResponseHeader(queryID uint16, opCode, rd byte) DNSHeader {
	header := DNSHeader{
		ID:      queryID,
		QDCount: 0,
		ANCount: 0,
		NSCount: 0,
		ARCount: 0,
	}

	header.SetQR(1)
	header.SetOPCODE(opCode)
	header.SetAA(0)
	header.SetTC(0)
	header.SetRD(rd)
	header.SetRA(0)
	header.SetZ(0)
	// 0 (no error) if OPCODE is 0 (standard query) else 4 (not implemented)
	if opCode == 0 {
		header.SetRCODE(0)
	} else {
		header.SetRCODE(4)
	}

	return header
}

// ToBytes converts the header to network byte order (big-endian)
func (h *DNSHeader) ToBytes() []byte {
	data := make([]byte, 12)
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
