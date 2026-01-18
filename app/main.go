package main

import (
	"errors"
	"fmt"
	"net"
)

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

	// Answer questions
	var answers []DNSAnswer
	for _, q := range questions {
		answer, err := CreateAnswerForQuestion(q)
		if err != nil {
			return nil, err
		}

		// Log answers
		ip := net.IP(answer.Data).String()
		fmt.Printf("Answer for %s: %s (TTL: %d)\n", q.Name, ip, answer.TTL)

		answers = append(answers, answer)
	}

	// Create response header
	responseHeader := CreateResponseHeader(header.ID, header.GetOPCODE(), header.GetRD())
	responseHeader.QDCount = header.QDCount
	responseHeader.ANCount = uint16(len(answers))

	// Build response
	var response []byte

	// 1. Add header
	response = append(response, responseHeader.ToBytes()...)

	// 2. Echo back the questions
	response = append(response, QuestionsToBytes(questions)...)

	// 3. Add answers
	for _, a := range answers {
		response = append(response, a.ToBytes()...)
	}

	return response, nil
}

func main() {
	fmt.Println("Logs from your program will appear here!")

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

		fmt.Printf("Received %d bytes from %s\n", size, source)

		response, err := HandleDNSQuery(buf[:size])
		if err != nil {
			fmt.Println("Error handling query:", err)
			continue
		}

		_, err = udpConn.WriteToUDP(response, source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}
