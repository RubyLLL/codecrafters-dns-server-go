package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"time"
)

// HandleDNSQuery processes a DNS query
func HandleDNSQuery(data []byte, resolver string) ([]byte, error) {
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

	if resolver != "" && header.GetOPCODE() == 0 {
		return ForwardDNSQuery(header, questions, resolver)
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

func ForwardDNSQuery(header DNSHeader, questions []DNSQuestion, resolver string) ([]byte, error) {
	var answers []DNSAnswer

	for _, q := range questions {
		resolverAnswers, err := ForwardQuestion(header, q, resolver)
		if err != nil {
			return nil, err
		}
		answers = append(answers, resolverAnswers...)
	}

	responseHeader := CreateResponseHeader(header.ID, header.GetOPCODE(), header.GetRD())
	responseHeader.QDCount = uint16(len(questions))
	responseHeader.ANCount = uint16(len(answers))

	var response []byte
	response = append(response, responseHeader.ToBytes()...)
	response = append(response, QuestionsToBytes(questions)...)
	for _, a := range answers {
		response = append(response, a.ToBytes()...)
	}

	return response, nil
}

func ForwardQuestion(header DNSHeader, question DNSQuestion, resolver string) ([]DNSAnswer, error) {
	queryHeader := header
	queryHeader.SetQR(0)
	queryHeader.QDCount = 1
	queryHeader.ANCount = 0
	queryHeader.NSCount = 0
	queryHeader.ARCount = 0

	query := append(queryHeader.ToBytes(), question.ToBytes()...)

	conn, err := net.Dial("udp", resolver)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return nil, err
	}

	if _, err := conn.Write(query); err != nil {
		return nil, err
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}

	resolverHeader, err := ParseHeader(buf[:n])
	if err != nil {
		return nil, err
	}

	_, offset, err := ParseQuestions(buf[:n], resolverHeader, 12)
	if err != nil {
		return nil, err
	}

	answers, _, err := ParseAnswers(buf[:n], offset, resolverHeader.ANCount)
	if err != nil {
		return nil, err
	}

	return answers, nil
}

func main() {
	fmt.Println("Logs from your program will appear here!")

	resolver := flag.String("resolver", "", "DNS resolver address")
	flag.Parse()
	if *resolver != "" {
		fmt.Println("Using resolver:", *resolver)
	}

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

		response, err := HandleDNSQuery(buf[:size], *resolver)
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
