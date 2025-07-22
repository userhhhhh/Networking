package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"strings"
)

const (
	sock5Version   = 0x05
	tcpconnect     = 0x01
	addrTypeIPv4   = 0x01
	addrTypeDomain = 0x03
	addrTypeIP6    = 0x04
)

var domainRules map[string]string

func getSNI(buf []byte, n int) (string, error) {
	//buf := make([]byte, 4096)
	//n, err := conn.Read(buf)
	//if err != nil {
	//	return "", err
	//}
	if n < 5 || buf[0] != 0x16 {
		return "", errors.New("not a TLS handshake")
	}

	// Skip to the start of ClientHello
	if buf[5] != 0x01 {
		return "", errors.New("not a ClientHello")
	}
	helloLength := int(buf[6])<<8 | int(buf[7])

	// Offset to the start of extensions
	offset := 43 // Skip fixed-length fields
	sessionIDLength := int(buf[offset])
	offset += 1 + sessionIDLength
	cipherSuiteLength := int(buf[offset])<<8 | int(buf[offset+1])
	offset += 2 + cipherSuiteLength
	compressionMethodLength := int(buf[offset])
	offset += 1 + compressionMethodLength

	// Read extensions
	for offset+4 <= helloLength {
		extensionType := int(buf[offset])<<8 | int(buf[offset+1])
		extensionLength := int(buf[offset+2])<<8 | int(buf[offset+3])
		offset += 4

		if extensionType == 0x00 { // SNI extension
			if offset+2 < helloLength {
				nameListLength := int(buf[offset])<<8 | int(buf[offset+1])
				if offset+2+nameListLength <= helloLength {
					// Skip name type (1 byte) and read length
					nameLength := int(buf[offset+3])<<8 | int(buf[offset+4])
					if offset+5+nameLength <= helloLength {
						return string(buf[offset+5 : offset+5+nameLength]), nil
					}
				}
			}
		}
		offset += extensionLength
	}

	return "", errors.New("SNI not found")
}

func ParseTLSClientHello(data []byte) (string, error) {
	if len(data) < 5 {
		return "", errors.New("data too short to be a valid TLS record")
	}

	// Check if it is a TLS handshake record
	if data[0] != 0x16 {
		return "", errors.New("not a TLS handshake record")
	}

	// The record length
	recordLength := binary.BigEndian.Uint16(data[3:5])
	if int(recordLength)+5 > len(data) {
		return "", errors.New("record length exceeds data length")
	}

	// The handshake message type (should be ClientHello)
	if data[5] != 0x01 {
		return "", errors.New("not a ClientHello message")
	}

	// Skip the handshake header (4 bytes) and parse the ClientHello
	pos := 5 + 4
	pos += 2 // Skip legacy version

	// Skip random (32 bytes)
	pos += 32

	// Skip session ID
	sessionIDLength := int(data[pos])
	pos += 1 + sessionIDLength

	// Skip cipher suites
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

func loadRules(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	domainRules = make(map[string]string)

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
			domainRules[strings.TrimPrefix(rule, "||")] = proxyAddr
		}
	}

	return scanner.Err()
}

func matchDomain(domain string) (string, bool) {
	//log.Println(domain)
	for rule, proxyAddr := range domainRules {
		if strings.HasPrefix(rule, "*.") && strings.HasSuffix(domain, rule[1:]) {
			return proxyAddr, true
		}
		if domain == rule {
			return proxyAddr, true
		}
	}
	return "", false
}

func process_connection(conn net.Conn) error {
	defer conn.Close()
	//fmt.Println("ConnConnected")
	if err := process_handshake(conn); err != nil {
		log.Println("Handshake error:", err)
		return err
	}
	//fmt.Println("HandShake")
	if err := process_request(conn); err != nil {
		//fmt.Println("Fail")
		log.Println("Request error:", err)
		return err
	}

	return nil
}
func process_handshake(conn net.Conn) error {

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

func ExtractHost(request []byte) (string, error) {
	//fmt.Println(string(request))

	reader := bufio.NewReader(bytes.NewReader(request))

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			log.Println("init1 :", err)
			//log.Println("init1 line :", string(line))
			return "", err
		}

		line = string(bytes.TrimSpace([]byte(line)))

		if line == "" {
			break
		}

		if strings.HasPrefix(line, "Host:") {
			//log.Println(line)
			return strings.TrimSpace(strings.TrimPrefix(line, "Host:")), nil
		}
	}

	return "", errors.New("Host header not found")
}

func getHostFromHttpRequest(data []byte) string {
	// 将字节切片转换为字符串
	httpRequest := string(data)

	// 查找"Host:"头的位置
	hostKey := "Host:"
	hostIndex := bytes.Index(data, []byte(hostKey))
	if hostIndex == -1 {
		//fmt.Println("Host header not found")
		return "" // 如果没有找到Host头，返回空字符串
	}
	//fmt.Println(string(data))
	// 计算Host值的起始位置，跳过"Host:"和可能的空格
	hostStart := hostIndex + len(hostKey)
	for hostStart < len(httpRequest) && httpRequest[hostStart] == ' ' {
		hostStart++
	}

	// 查找到Host值的终止位置（假设是以换行符结尾）
	hostEnd := hostStart
	for hostEnd < len(httpRequest) && httpRequest[hostEnd] != '\r' && httpRequest[hostEnd] != '\n' {
		hostEnd++
	}

	if hostEnd > len(httpRequest) {
		hostEnd = len(httpRequest)
	}

	// 截取值并返回
	//fmt.Println("hostStart:", hostStart)
	//fmt.Println("hostEnd:", hostEnd)
	//fmt.Println("httpRequest:", httpRequest[hostStart:hostEnd])
	return httpRequest[hostStart:hostEnd]
}

func process_request(conn net.Conn) error {
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

	//log.Println("woc")

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

	//log.Println("jjjjj", host)
	//log.Println("nononononon")

	proxyAddr, _ := matchDomain(host)

	//log.Println("targetConn:", proxyAddr)

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

func main() {
	loadRules("./rules.txt")
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
		go process_connection(conn)
	}
}
