package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"

	"golang.org/x/net/proxy"
	"net/netip"
)

const (
	sock5Version   = 0x05
	tcpconnect     = 0x01
	addrTypeIPv4   = 0x01
	addrTypeDomain = 0x03
	addrTypeIP6    = 0x04
)

var ipRules []netip.Prefix
var domain_ip_Rules map[string]string

func load_ip_Rules(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	ipRules = []netip.Prefix{}
	domain_ip_Rules = make(map[string]string)

	scanner := bufio.NewScanner(file)
	// scanner.Scan()每次调用会尝试读取下一行文本。如果成功读取到一行文本返回 true；如果到达数据流的末尾或者发生错误，返回 false。
	// scanner内部会维护一个缓冲区,成功调用 scanner.Scan()后，该行文本会被存储在这个缓冲区中。
	// scanner.Text()根据 scanner当前缓冲区中的行文本内容返回一个字符串
	// strings.TrimSpace():标准函数，去除字符串两端的空白字符
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "[") {
			continue
		}

		// strings.Fields(line)：标准函数，将字符串 line 按照空白字符分割成一个字符串切片
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		rule := parts[0]
		proxyAddr := parts[1]

		if strings.HasPrefix(rule, "||") {
			// Domain rule: 使用去除开头 || 后的域名作为键
			domain_ip_Rules[strings.TrimPrefix(rule, "||")] = proxyAddr
		} else if strings.Contains(rule, "/") {
			// IP rule: netip.ParsePrefix(rule)中 rule要求是一个与 ip有关的字符串，然后对 rule进行解析，得到 prefix
			prefix, err := netip.ParsePrefix(rule)
			if err == nil {
				ipRules = append(ipRules, prefix)
			}
		}
	}

	return scanner.Err()
}

func match_ip_Domain(domain string) (string, bool) {
	for rule, proxyAddr := range domain_ip_Rules {
		if strings.HasPrefix(rule, "*.") && strings.HasSuffix(domain, rule[1:]) {
			log.Println("Matching_domain")
			return proxyAddr, true
		}
		if domain == rule {
			log.Println("Matching_domain")
			return proxyAddr, true
		}
	}
	log.Println(domain)
	log.Println("Not matching_domain")
	return "", false
}

func process_ip_connection(conn net.Conn) error {
	defer conn.Close()
	if err := process_ip_handshake(conn); err != nil {
		log.Println("Handshake error:", err)
		return err
	}
	//fmt.Println("hhhhhhhh")
	if err := process_ip_request(conn); err != nil {
		log.Println("Request error:", err)
		return err
	}
	return nil
}

func process_ip_handshake(conn net.Conn) error {
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

	response := []byte{sock5Version, 0x00}
	_, err2 := conn.Write(response)
	if err2 != nil {
		return err2
	}

	return nil
}

func process_ip_request(conn net.Conn) error {
	buf := make([]byte, 4)
	//con.http(buf)
	_, err := conn.Read(buf)
	if err != nil {
		return err
	}
	if buf[0] != sock5Version {
		return errors.New("sock5 not supported")
	}
	if buf[1] != tcpconnect {
		return errors.New("tcpconnect not supported")
	}

	var addr string
	var proxyAddr string
	switch buf[3] {
	case addrTypeIPv4:
		IPv4buf := make([]byte, net.IPv4len)
		if _, err1 := io.ReadFull(conn, IPv4buf); err1 != nil {
			return err1
		}
		addr = net.IP(IPv4buf).String()
		ip := netip.MustParseAddr(addr)
		for _, prefix := range ipRules {
			if prefix.Contains(ip) {
				log.Println("Matching_IP")
				proxyAddr = "0.0.0.0:7890"
				break
			}
		}
	case addrTypeDomain:
		buf := make([]byte, 1)
		if _, err1 := io.ReadFull(conn, buf); err1 != nil {
			return err1
		}
		Domainlength := int(buf[0])
		Domainbuf := make([]byte, Domainlength)
		if _, err1 := io.ReadFull(conn, Domainbuf); err1 != nil {
			return err1
		}
		addr = string(Domainbuf)
		if proxyAddr, _ = match_ip_Domain(addr); proxyAddr == "" {
			proxyAddr = "0.0.0.0:7890"
		}
	case addrTypeIP6:
		IPv6buf := make([]byte, net.IPv6len)
		if _, err1 := io.ReadFull(conn, IPv6buf); err1 != nil {
			return err1
		}
		addr = net.IP(IPv6buf).String()
	default:
		return nil
	}
	//fmt.Println("fuck")

	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return err
	}
	port := binary.BigEndian.Uint16(buf)

	targetAddr := net.JoinHostPort(addr, strconv.Itoa(int(port)))

	//fmt.Println("ffffffff")

	dialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
	if err != nil {
		log.Println("Failed to create SOCKS5 dialer:", err)
		return err
	}

	//fmt.Println("oooooooooo")

	//fmt.Println(targetAddr)

	targetConn, err := dialer.Dial("tcp", targetAddr)
	if err != nil {
		fmt.Println("Failed to create target connection:", err)
		return err
	}

	//fmt.Println("iiiiiiiiiii")
	defer targetConn.Close()

	response := []byte{sock5Version, 0x00, 0x00, addrTypeIPv4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	if _, err := conn.Write(response); err != nil {
		return err
	}

	//fmt.Println("kkkkkkkkk")

	go io.Copy(targetConn, conn)
	io.Copy(conn, targetConn)

	return nil
}

func rules_ip() {
	if err := load_ip_Rules("rules.txt"); err != nil {
		log.Fatal(err)
	}

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
		go process_ip_connection(conn)
	}
}
