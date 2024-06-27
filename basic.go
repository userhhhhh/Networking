package basic

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
)

const (
	sock5Version   = 0x05
	tcpconnect     = 0x01
	addrTypeIPv4   = 0x01
	addrTypeDomain = 0x03
	addrTypeIP6    = 0x04
)

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

func process_request(conn net.Conn) error {
	defer conn.Close()
	buf := make([]byte, 4)
	//_, err := io.ReadFull(conn, buf)
	_, err := conn.Read(buf)
	//fmt.Println("THERE")
	if err != nil {
		//fmt.Println("Read error:", err)
		return err
	}
	//fmt.Println("hhhhhhhhhhhhhh")
	if buf[0] != sock5Version {
		return errors.New("sock5 not supported")
	}
	if buf[1] != tcpconnect {
		return errors.New("tcpconnect not supported")
	}

	//fmt.Println("tcpconnect")
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
		//addr = string(IPv4buf)
	case addrTypeDomain:
		fmt.Println(2)
		buf := make([]byte, 1)
		if _, err1 := io.ReadFull(conn, buf); err1 != nil {
			//fmt.Println("Read error1:", err1)
			return err1
		}
		Domainlength := int(buf[0])
		fmt.Println(Domainlength)
		Domainbuf := make([]byte, Domainlength)
		if _, err1 := io.ReadFull(conn, Domainbuf); err1 != nil {
			//fmt.Println("Read error2:", err1)
			return err1
		}
		//addr = net.IP(buf).String()
		addr = string(Domainbuf)
	case addrTypeIP6:
		fmt.Println(3)
		IPv6buf := make([]byte, net.IPv6len)
		if _, err1 := io.ReadFull(conn, IPv6buf); err1 != nil {
			//fmt.Println("Read error3:", err1)
			return err1
		}
		//addr = string(IPv6buf)
		addr = net.IP(IPv6buf).String()
	default:
		//fmt.Println("Unsupported address type:")
		return nil
	}

	//fmt.Println("fuck")

	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return err
	}

	//fmt.Println("fffffff")
	port := binary.BigEndian.Uint16(buf)
	targetAddr := net.JoinHostPort(addr, strconv.Itoa(int(port)))
	//fmt.Println("kkkkkkkkk")
	//将 buf 中前两个字节解析为一个端口号，然后将该端口号与 addr 合并成一个格式为 "address:port" 的目标地址字符串

	//fmt.Println(addr, targetAddr)
	targetConn, err := net.Dial("tcp", targetAddr)
	if err != nil {
		//fmt.Println("ConnectedFail")
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

func main() {
	listener, err := net.Listen("tcp", "0.0.0.0:9768")
	if err != nil {
		log.Fatal(err)
		return
	}
	//fmt.Println("Connected")
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

//备注：socks5协议：https://blog.csdn.net/qq_40873884/article/details/123636767
//备注：文章中错误：第三步 DST.ADDR部分应该是：如果是 Domain，该字段的第一个字节是域名长度，剩下字节为域名
//备注：借鉴了 chatgpt
/*备注：addr = net.IP(IPv4buf).String()与 addr = string(IPv4buf)的区别：
a.两者目的都是将字符切片转化成字符序列
b.在 Go 语言中，将字节切片转换为字符串就是将字节解释为 UTF-8 编码的 Unicode 字符序列。
第二种情况中，如果 IPv4buf 中包含有效的 UTF-8 字符序列，它们将被正确地转换为对应的 Unicode 字符，
但是如果 IPv4buf 中包含非 UTF-8 编码的字节序列，则这种转换可能会导致数据不正确。
c.net.IP(IPv4buf).String() 更适合处理和表示 IP 地址，它会确保正确地将字节切片转换为标准的 IP 地址字符串表示形式。
而 string(IPv4buf) 更适合处理一般的文本数据转换，对于 IP 地址的处理不如 net.IP 类型的转换精确和可靠。
*/
