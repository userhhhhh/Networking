package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"strings"
)

var domain_tls_Rules map[string]string

func ParseTLSClientHello(data []byte) (string, error) {
	if len(data) < 5 {
		return "", errors.New("data too short to be a valid TLS record")
	}

	if data[0] != 0x16 {
		return "", errors.New("not a TLS handshake record")
	}

	recordLength := binary.BigEndian.Uint16(data[3:5])
	if int(recordLength)+5 > len(data) {
		return "", errors.New("record length exceeds data length")
	}

	if data[5] != 0x01 {
		return "", errors.New("not a ClientHello message")
	}

	pos := 5 + 4
	pos += 2

	pos += 32

	sessionIDLength := int(data[pos])
	pos += 1 + sessionIDLength

	cipherSuitesLength := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2 + cipherSuitesLength

	// Skip compression methods
	compressionMethodsLength := int(data[pos])
	pos += 1 + compressionMethodsLength

	// Check for extensions
	if pos+2 > len(data) {
		return "", errors.New("data too short to contain extensions length")
	}
	extensionsLength := binary.BigEndian.Uint16(data[pos : pos+2])
	pos += 2

	if pos+int(extensionsLength) > len(data) {
		return "", errors.New("extensions length exceeds data length")
	}

	// Parse extensions
	for pos < len(data) {
		if pos+4 > len(data) {
			return "", errors.New("data too short to read extension header")
		}

		extensionType := binary.BigEndian.Uint16(data[pos : pos+2])
		extensionLength := binary.BigEndian.Uint16(data[pos+2 : pos+4])
		pos += 4

		if pos+int(extensionLength) > len(data) {
			return "", errors.New("extension length exceeds data length")
		}

		if extensionType == 0x0000 { // Server Name extension
			namesLen := binary.BigEndian.Uint16(data[pos : pos+2])
			pos += 2
			totalNameLen := int(namesLen)

			for totalNameLen > 0 {
				if pos+3 > len(data) {
					return "", errors.New("data too short to read server name")
				}

				nameType := data[pos]
				nameLen := binary.BigEndian.Uint16(data[pos+1 : pos+3])
				pos += 3
				totalNameLen -= 3 + int(nameLen)

				if nameType == 0 {
					if pos+int(nameLen) > len(data) {
						return "", errors.New("server name length exceeds data length")
					}

					return string(data[pos : pos+int(nameLen)]), nil
				}

				pos += int(nameLen)
			}
		} else {
			pos += int(extensionLength)
		}
	}

	return "", errors.New("SNI not found")
}

func load_tls_Rules(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	domain_tls_Rules = make(map[string]string)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "[") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		rule := parts[0]
		proxyAddr := parts[1]

		if strings.HasPrefix(rule, "||") {
			// Domain rule: 使用去除开头 || 后的域名作为键
			domain_tls_Rules[strings.TrimPrefix(rule, "||")] = proxyAddr
		}
	}

	return scanner.Err()
}

func match_tls_Domain(domain string) (string, bool) {
	//log.Println(domain)
	for rule, proxyAddr := range domain_tls_Rules {
		if strings.HasPrefix(rule, "*.") && strings.HasSuffix(domain, rule[1:]) {
			return proxyAddr, true
		}
		if domain == rule {
			return proxyAddr, true
		}
	}
	return "", false
}

func process_tls_connection(conn net.Conn) error {
	defer conn.Close()
	//fmt.Println("ConnConnected")
	if err := process_tls_handshake(conn); err != nil {
		log.Println("Handshake error:", err)
		return err
	}
	//fmt.Println("HandShake")
	if err := process_tls_request(conn); err != nil {
		//fmt.Println("Fail")
		log.Println("Request error:", err)
		return err
	}

	return nil
}
func process_tls_handshake(conn net.Conn) error {

	buf := make([]byte, 2)
	_, err := io.ReadFull(conn, buf)
	if err != nil {
		return err
	}
	if buf[0] != sock5Version {
		return errors.New("sock5 not supported")
	}
	nMethods := buf[1]
	methods := make([]byte, nMethods)
	_, err1 := io.ReadFull(conn, methods)
	if err1 != nil {
		return err1
	}

	response := make([]byte, 2)
	response[0] = sock5Version
	response[1] = 0x00
	_, err2 := conn.Write(response)
	if err2 != nil {
		return err2
	}

	return nil
}

func process_tls_request(conn net.Conn) error {
	defer conn.Close()

	buf1 := make([]byte, 4096)
	n1, err := conn.Read(buf1)
	if err != nil {
		return err
	}

	response := []byte{sock5Version, 0x00, 0x00, addrTypeIPv4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	if _, err := conn.Write(response); err != nil {
		return err
	}

	request := make([]byte, 4096)
	n, err := conn.Read(request)
	if err != nil {
		return err
	}

	//fmt.Println(string(request))
	//log.Println("tmd")

	host := getHostFromHttpRequest(request)

	if host == "" {
		//host, err = getSNI(request, n)
		host, err = ParseTLSClientHello(request)
		if err != nil {
			return err
		}
	}

	proxyAddr, _ := match_tls_Domain(host)

	targetConn, err := net.Dial("tcp", proxyAddr)
	//log.Println("fuck")
	if err != nil {
		return err
	}
	defer targetConn.Close()

	//log.Println("hhhhhhh")
	_, err = targetConn.Write([]byte{0x05, 0x01, 0x00})
	if err != nil {
		return err
	}

	buf := make([]byte, 4096)
	//log.Println("ffffffff")
	_, err = targetConn.Read(buf)
	if err != nil {
		return err
	}
	_, err = targetConn.Write(buf1[:n1])
	if err != nil {
		return err
	}
	_, err = targetConn.Read(buf)
	if err != nil {
		return err
	}

	targetConn.Write(request[:n])

	go io.Copy(targetConn, conn)
	io.Copy(conn, targetConn)

	return nil
}

func rules_tls() {
	load_tls_Rules("./rules.txt")
	listener, err := net.Listen("tcp", "0.0.0.0:9768")
	if err != nil {
		log.Fatal(err)
		return
	}
	defer listener.Close()
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Fatal(err)
			return
		}
		go process_tls_connection(conn)
	}
}
