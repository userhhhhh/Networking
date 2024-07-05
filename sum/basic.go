package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
)

func process_basic(conn net.Conn) error {
	defer conn.Close()
	if err := process_basic_handshake(conn); err != nil {
		log.Println("Handshake error:", err)
		return err
	}
	if err := process_basic_request(conn); err != nil {
		log.Println("Request error:", err)
		return err
	}

	return nil
}
func process_basic_handshake(conn net.Conn) error {
	//defer conn.Close()
	//错误：这里不能将conn关掉，因为后面处理 request还要用

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

func process_basic_request(conn net.Conn) error {
	defer conn.Close()
	buf := make([]byte, 4)
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
	switch buf[3] {
	case addrTypeIPv4:
		fmt.Println(1)
		IPv4buf := make([]byte, net.IPv4len)
		if _, err1 := io.ReadFull(conn, IPv4buf); err1 != nil {
			fmt.Println("Read error:", err1)
			return err1
		}
		addr = net.IP(IPv4buf).String()
	case addrTypeDomain:
		fmt.Println(2)
		buf := make([]byte, 1)
		if _, err1 := io.ReadFull(conn, buf); err1 != nil {
			return err1
		}
		Domainlength := int(buf[0])
		fmt.Println(Domainlength)
		Domainbuf := make([]byte, Domainlength)
		if _, err1 := io.ReadFull(conn, Domainbuf); err1 != nil {
			return err1
		}
		addr = string(Domainbuf)
	case addrTypeIP6:
		fmt.Println(3)
		IPv6buf := make([]byte, net.IPv6len)
		if _, err1 := io.ReadFull(conn, IPv6buf); err1 != nil {
			return err1
		}
		addr = net.IP(IPv6buf).String()
	default:
		return nil
	}

	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return err
	}

	port := binary.BigEndian.Uint16(buf)
	targetAddr := net.JoinHostPort(addr, strconv.Itoa(int(port)))

	//将 buf 中前两个字节解析为一个端口号，然后将该端口号与 addr 合并成一个格式为 "address:port" 的目标地址字符串

	targetConn, err := net.Dial("tcp", targetAddr)
	if err != nil {
		return err
	}
	defer targetConn.Close()

	response := []byte{sock5Version, 0x00, 0x00, addrTypeIPv4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	if _, err := conn.Write(response); err != nil {
		return err
	}
	go io.Copy(targetConn, conn)
	io.Copy(conn, targetConn)

	return nil
}

func basic() {
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
		go process_basic(conn)
	}
}
