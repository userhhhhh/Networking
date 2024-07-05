package main

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"strings"
)

var domain_http_Rules map[string]string

func load_http_Rules(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	domain_http_Rules = make(map[string]string)

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
			domain_http_Rules[strings.TrimPrefix(rule, "||")] = proxyAddr
		}
	}

	return scanner.Err()
}

func match_http_Domain(domain string) (string, bool) {
	log.Println(domain)
	for rule, proxyAddr := range domain_http_Rules {
		if strings.HasPrefix(rule, "*.") && strings.HasSuffix(domain, rule[1:]) {
			return proxyAddr, true
		}
		if domain == rule {
			return proxyAddr, true
		}
	}
	return "", false
}

func process_http_connection(conn net.Conn) error {
	defer conn.Close()
	//fmt.Println("ConnConnected")
	if err := process_http_handshake(conn); err != nil {
		log.Println("Handshake error:", err)
		return err
	}
	//fmt.Println("HandShake")
	if err := process_http_request(conn); err != nil {
		//fmt.Println("Fail")
		log.Println("Request error:", err)
		return err
	}

	return nil
}
func process_http_handshake(conn net.Conn) error {

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

	//fmt.Println("hostStart:", hostStart)
	//fmt.Println("hostEnd:", hostEnd)
	//fmt.Println("httpRequest:", httpRequest[hostStart:hostEnd])
	return httpRequest[hostStart:hostEnd]
}

func process_http_request(conn net.Conn) error {
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

	host := getHostFromHttpRequest(request)

	proxyAddr, _ := match_http_Domain(host)
	targetConn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		return err
	}
	defer targetConn.Close()
	_, err = targetConn.Write([]byte{0x05, 0x01, 0x00})
	if err != nil {
		return err
	}

	buf := make([]byte, 4096)
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

func rules_http() {
	load_http_Rules("./rules.txt")
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
		go process_http_connection(conn)
	}
}
