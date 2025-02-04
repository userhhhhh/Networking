package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	listenAddr = "0.0.0.0:9768"
)

var rootCert *x509.Certificate
var rootKey crypto.PrivateKey

func loadRootCA(certFile, keyFile string) (*x509.Certificate, crypto.PrivateKey, error) {
	// Load the certificate file
	certPEM, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, nil, err
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, nil, os.ErrInvalid
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, err
	}

	// Load the private key file
	keyPEM, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, nil, err
	}
	block, _ = pem.Decode(keyPEM)
	if block == nil {
		return nil, nil, os.ErrInvalid
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// If it's not a PKCS1 key, try to parse it as a PKCS8 key
		keyInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, nil, err
		}
		return cert, keyInterface, nil
	}
	return cert, key, nil
}

func main() {
	var err1 error
	rootCert, rootKey, err1 = loadRootCA("server.crt", "server.key")
	if err1 != nil {
		log.Fatalf("Failed to load root CA: %v", err1)
		return
	}
	fmt.Println("hhhhhhhhhhhhhhhh")
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", listenAddr, err)
	}
	defer listener.Close()
	fmt.Printf("Listening on %s\n", listenAddr)

	for {
		clientConn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}

		go handleClient(clientConn)
	}
}

func process_handshake(conn net.Conn) (string, int, error) {
	buf := make([]byte, 2)
	_, err := io.ReadFull(conn, buf)
	if err != nil {
		return "", 0, err
	}
	if buf[0] != 0x05 {
		return "", 0, errors.New("sock5 not supported")
	}
	nMethods := buf[1]
	methods := make([]byte, nMethods)
	_, err1 := io.ReadFull(conn, methods)
	if err1 != nil {
		return "", 0, err1
	}

	response := make([]byte, 2)
	response[0] = 0x05
	response[1] = 0x00
	_, err2 := conn.Write(response)
	if err2 != nil {
		return "", 0, err2
	}

	buf = make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return "", 0, err
	}
	if buf[0] != 0x05 {
		return "", 0, errors.New("socks5 not supported")
	}
	if buf[1] != 0x01 {
		return "", 0, errors.New("only support connect command")
	}
	if buf[2] != 0x00 {
		return "", 0, errors.New("only support no authentication required")
	}
	var addr string
	switch buf[3] {
	case 0x01:
		addr = net.IP(buf[4:8]).String()
	case 0x03:
		addr = string(buf[5 : n-2])
	case 0x04:
		addr = fmt.Sprintf("%d.%d.%d.%d:%d", buf[4], buf[5], buf[6], buf[7], buf[8])
	default:
		return "", 0, nil
	}
	port := int(binary.BigEndian.Uint16(buf[n-2:]))

	response1 := []byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	if _, err := conn.Write(response1); err != nil {
		return "", 0, err
	}

	return addr, port, nil
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
	//fmt.Println("listandchange")
	for i := 0; i < 50; i++ {
		response, err := http.ReadResponse(bufio.NewReader(targetConn), nil)
		if err != nil {
			fmt.Println("ReadResponse error:", err)
			return
		}

		responseBytes, err := io.ReadAll(response.Body)
		//fmt.Println("responseBytes:", string(responseBytes))
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

		//fmt.Println("ResponseStr:", responseStr)

		responseStr = strings.Replace(responseStr, "百度", "抽象", -1)

		modifiedResponse := []byte(responseStr)

		bodylen = len(modifiedResponse)

		Newres := response
		defer response.Body.Close()
		Newres.Body = ioutil.NopCloser(bytes.NewReader(modifiedResponse))
		Newres.Header.Del("Content-Encoding")
		//Newres.Header.Del("Transfer-Encoding")
		Newres.Header.Set("Content-Length", fmt.Sprintf("%d", bodylen))
		Newres.ContentLength = int64(bodylen)

		var serializedResponse bytes.Buffer
		err = Newres.Write(&serializedResponse)
		if err != nil {
			return
		}

		_, err = conn.Write(serializedResponse.Bytes())
		if err != nil {
			return
		}
	}
}

func handlerequest(clientTLS, serverTLS net.Conn) error {
	res, err := http.ReadRequest(bufio.NewReader(clientTLS))
	if err != nil {
		fmt.Println("ReadRequest error:", err)
		return err
	}
	encoding := res.Header.Get("Accept-Encoding")
	if flag := strings.Contains(encoding, "gzip"); flag == false {
		res.Header.Del("Accept-Encoding")
	} else {
		res.Header.Set("Accept-Encoding", "gzip")
	}
	var serializedResponse bytes.Buffer
	err = res.Write(&serializedResponse)
	if err != nil {
		return err
	}
	_, err = serverTLS.Write(serializedResponse.Bytes())
	if err != nil {
		fmt.Println("Write error:", err)
		return err
	}
	return nil
}

func handleClient(clientConn net.Conn) {
	defer clientConn.Close()

	serverAddr1, port, err := process_handshake(clientConn)
	if err != nil {
		return
	}

	//serverAddr = "www.example.com:443"
	port = 443

	serverAddr2 := net.JoinHostPort(serverAddr1, strconv.Itoa(int(port)))

	serverTLS, err := tls.Dial("tcp", serverAddr2, nil)
	if err != nil {
		log.Printf("Failed to connect to server: %v", err)
		return
	}
	defer serverTLS.Close()

	clientTLS, err := setupTLS(clientConn, true, serverAddr1)
	if err != nil {
		log.Printf("Failed to setup TLS for client: %v", err)
		return
	}
	defer clientTLS.Close()

	go func() {
		for {
			err := handlerequest(clientTLS, serverTLS)
			if err != nil {
				return
			}
		}
	}()
	//go io.Copy(serverTLS, clientTLS)

	listandchange(clientTLS, serverTLS)

	io.Copy(clientTLS, serverTLS)
}

func setupTLS(conn net.Conn, isClient bool, domain string) (*tls.Conn, error) {
	var tlsConn *tls.Conn
	if isClient {
		// Generate a certificate for the domain
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("failed to generate private key: %v", err)
		}

		// Create a self-signed certificate.
		certTemplate := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject: pkix.Name{
				CommonName:   domain,
				Organization: []string{"hhh"},
			},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(365 * 24 * time.Hour),
			KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
			DNSNames:              []string{domain},
		}

		bytes, err := x509.CreateCertificate(rand.Reader, certTemplate, rootCert, &privateKey.PublicKey, rootKey)
		if err != nil {
			return nil, fmt.Errorf("failed to create certificate: %v", err)
		}

		// PEM encode the certificate (this is a standard TLS encoding).
		certPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: bytes,
		})

		// PEM encode the private key.
		keyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
		})

		// Create a TLS cert using the private key and certificate.
		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return nil, fmt.Errorf("invalid key pair: %v", err)
		}

		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			// Use self-signed certificates, don't verify the client certificate
			InsecureSkipVerify: true,
		}
		tlsConn = tls.Server(conn, tlsConfig)
	} else {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
		}
		tlsConn = tls.Client(conn, tlsConfig)
	}

	if err := tlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf("TLS handshake failed: %v", err)
	}
	return tlsConn, nil
}

func transfer(clientTLS, serverTLS *tls.Conn) {
	//go io.Copy(serverTLS, clientTLS)
	//io.Copy(clientTLS, serverTLS)
	done := make(chan struct{})

	go func() {
		io.Copy(serverTLS, clientTLS)
		serverTLS.CloseWrite()
		done <- struct{}{}
	}()

	go func() {
		io.Copy(clientTLS, serverTLS)
		clientTLS.CloseWrite()
		done <- struct{}{}
	}()

	<-done
	<-done
}
