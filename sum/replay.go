package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
)

var domain_replay_Rules map[string]string

func load_replay_Rules(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	domain_replay_Rules = make(map[string]string)

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
			domain_replay_Rules[strings.TrimPrefix(rule, "||")] = proxyAddr
		}
	}

	return scanner.Err()
}

func match_replay_Domain(domain string) (string, bool) {
	log.Println(domain)
	for rule, proxyAddr := range domain_replay_Rules {
		if strings.HasPrefix(rule, "*.") && strings.HasSuffix(domain, rule[1:]) {
			return proxyAddr, true
		}
		if domain == rule {
			return proxyAddr, true
		}
	}
	return "", false
}

func process_replay_connection(conn net.Conn) error {
	defer conn.Close()
	if err := process_replay_handshake(conn); err != nil {
		log.Println("Handshake error:", err)
		return err
	}
	if err := process_replay_request(conn); err != nil {
		log.Println("Request error:", err)
		return err
	}

	return nil
}
func process_replay_handshake(conn net.Conn) error {
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

func decompressGzip(data []byte) ([]byte, error) {
	reader := bytes.NewReader(data)

	gzipReader, err := gzip.NewReader(reader)
	if err != nil {
		return nil, err
	}
	defer gzipReader.Close()

	// 读取解压缩后的数据
	decompressedData, err := io.ReadAll(gzipReader)
	if err != nil {
		return nil, err
	}

	return decompressedData, nil
}

func listandchange(conn, targetConn net.Conn) {
	for i := 0; i < 5; i++ {
		response, err := http.ReadResponse(bufio.NewReader(targetConn), nil)
		if err != nil {
			return
		}

		responseBytes, err := io.ReadAll(response.Body)
		fmt.Println("responseBytes:", string(responseBytes))
		if err != nil {
			panic(err)
			return
		}

		var res []byte
		switch response.Header.Get("Content-Encoding") {
		case "gzip":
			res, err = decompressGzip(responseBytes)
			if err != nil {
				return
			}
		default:
			res = responseBytes
		}

		bodylen := len(res)

		responseStr := string(res)

		fmt.Println("ResponseStr:", responseStr)

		responseStr = strings.Replace(responseStr, "PKU", "SJTU", -1)

		modifiedResponse := []byte(responseStr)

		bodylen = len(modifiedResponse)

		Newres := response
		response.Body.Close()
		Newres.Body = ioutil.NopCloser(bytes.NewReader(modifiedResponse))
		Newres.Header.Del("Content-Encoding")
		Newres.Header.Del("Transfer-Encoding")
		Newres.Header.Set("Content-Length", fmt.Sprintf("%d", bodylen))
		Newres.ContentLength = int64(bodylen)

		var serializedResponse bytes.Buffer
		err = Newres.Write(&serializedResponse)
		if err != nil {
			return
		}

		//NewBuf, _ := responseToByteSlice(Newres)

		_, err = conn.Write(serializedResponse.Bytes())
		if err != nil {
			return
		}
	}
}

func process_replay_request(conn net.Conn) error {
	defer conn.Close()

	buf1 := make([]byte, 4096)
	n1, err := conn.Read(buf1)
	if err != nil {
		return err
	}

	response1 := []byte{sock5Version, 0x00, 0x00, addrTypeIPv4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	if _, err := conn.Write(response1); err != nil {
		return err
	}

	request := make([]byte, 4096)
	n, err := conn.Read(request)
	if err != nil {
		return err
	}

	host := getHostFromHttpRequest(request)

	proxyAddr, _ := match_replay_Domain(host)
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

	listandchange(conn, targetConn)

	io.Copy(conn, targetConn)

	return nil
}

func replay() {
	load_replay_Rules("./rules.txt")
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
		go process_replay_connection(conn)
	}
}
