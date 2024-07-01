package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

func process_connection(conn net.Conn, proxyAddr string) error {
	defer conn.Close()
	targetConn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		return err
	}
	defer targetConn.Close()

	go io.Copy(targetConn, conn)
	io.Copy(conn, targetConn)

	return nil
}

func getPIDByPort(port int) (int, error) {
	cmd := exec.Command("cmd", "/c", "netstat", "-ano", "|", "findstr", strconv.Itoa(port))
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return 0, err
	}
	reg := regexp.MustCompile(`\s+`)
	s := reg.ReplaceAllString(out.String(), " ")
	s = strings.TrimSpace(s)
	ss := strings.Split(s, " ")
	pid, err := strconv.Atoi(ss[len(ss)-1])
	if err != nil {
		return 0, err
	}
	return pid, nil
}

func getProgramNameByPID(pid int) (string, error) {
	cmd := exec.Command("cmd", "/c", "tasklist", "|", "findstr", strconv.Itoa(pid))
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return "", err
	}
	reg := regexp.MustCompile(`\s+`)
	s := reg.ReplaceAllString(out.String(), " ")
	s = strings.TrimSpace(s)
	ss := strings.Split(s, " ")
	return ss[0], nil
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
			log.Fatal("erroe:", err)
			return
		}
		clientAddr := conn.RemoteAddr().(*net.TCPAddr)
		clientPort := clientAddr.Port

		fmt.Println(clientPort)

		pid, err := getPIDByPort(clientPort)
		if err != nil {
			fmt.Println("error:", err)
			return
		}
		programName, err := getProgramNameByPID(pid)
		if err != nil {
			fmt.Println("error:", err)
			return
		}
		var proxyAddr string
		log.Println("name:", programName)
		if programName == "msedge.exe" {
			proxyAddr = "0.0.0.0:7890"
		}
		//fmt.Println("hhhhhh", proxyAddr)

		go process_connection(conn, proxyAddr)
	}
}
