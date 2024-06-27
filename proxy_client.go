package main

import (
	"errors"
	"io"
	"log"
	"net"
)

const (
	sock5Version   = 0x05
	tcpconnect     = 0x01
	addrTypeIPv4   = 0x01
	addrTypeDomain = 0x03
	addrTypeIP6    = 0x04
	proxy2addr     = "0.0.0.0:7890"
)

func process_connection(conn net.Conn) error {
	defer conn.Close()

	//--------删除上线 1--------
	if err := process_handshake(conn); err != nil {
		log.Println("Handshake error:", err)
		return err
	}
	//--------删除下线 1--------

	if err := process_request(conn); err != nil {
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

func process_request(conn net.Conn) error {
	defer conn.Close()
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		return err
	}
	if buf[0] != sock5Version {
		return errors.New("sock5 not supported")
	}
	if buf[1] != tcpconnect {
		return errors.New("tcpconnect not supported")
	}

	targetConn, err := net.Dial("tcp", proxy2addr)
	if err != nil {
		return err
	}

	defer targetConn.Close()

	//--------删除上线 2--------
	_, err = targetConn.Write([]byte{0x05, 0x01, 0x00})
	if err != nil {
		return err
	}
	buf2 := make([]byte, 256)
	n2, err2 := targetConn.Read(buf2)
	if err2 != nil {
		return err2
	}
	if err2 != nil || buf2[1] != 0x00 || n2 < 2 {
		return err2
	}
	//--------删除下线 2--------
	//片段 1和片段 2可以同时删除的原因：这里可以讲客户端直接和代理 2握手
	//单独的第二片段不能删除的原因：代理 2根据协议会去握手，这个时候代理 1就不能不握手了

	_, err = targetConn.Write(buf[:n])
	if err != nil {
		return err
	}

	go io.Copy(targetConn, conn)
	io.Copy(conn, targetConn)

	return nil
}

func main() {
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
