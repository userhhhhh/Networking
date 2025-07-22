# Networking

A comprehensive SOCKS5 proxy implementation with advanced networking capabilities, including traffic routing, protocol analysis, and traffic manipulation.

## 🚀 Features

- **Basic SOCKS5 Proxy Server** - Complete implementation of SOCKS5 protocol (RFC 1928)
- **Multi-level Proxy Client** - Support for chaining multiple proxy servers
- **IP-based Routing** - Route traffic based on IP prefixes and ranges
- **HTTP/TLS Traffic Analysis** - Inspect and route based on HTTP headers and TLS SNI
- **UDP Forwarding** - Support for UDP protocol alongside TCP
- **TLS Interception** - Certificate generation and HTTPS traffic inspection
- **HTTP Capture & Replay** - Capture, modify and replay HTTP traffic
- **PID-based Routing** - Route traffic based on process identifiers
- **Transparent Proxy Mode** - Intercept traffic using iptables without client configuration

## 📂 Project Structure

```
.
├── basic.go                 # Core SOCKS5 server implementation
├── proxy_client.go          # SOCKS5 proxy client for multi-level proxying
├── ip-routing/              # IP-based routing implementation
├── http-tls-routing/        # HTTP and TLS traffic analysis and routing
├── udp-forward/             # UDP protocol support
├── tls-hijack/              # TLS certificate hijacking and HTTPS interception
├── http-replay/             # HTTP traffic capture and replay functionality
├── pid-routing/             # Process ID based routing
└── sum/                     # Comprehensive integration of all components
```

## 🛠️ Installation

Clone the repository:

```bash
git clone https://github.com/userhhhhh/Networking.git
cd Networking
```

Build the core proxy server:

```bash
go build -o proxy basic.go
```

Or build specific components:

```bash
cd ip-routing
go build -o ip-router .
```

## 📋 Usage

### Basic SOCKS5 Proxy

Run the basic SOCKS5 server:

```bash
./proxy
```

The server will listen on port 1080 by default.

### IP-based Routing

Start the IP routing proxy:

```bash
cd ip-routing
./ip-router
```

Configure routing rules in `rules.txt`:

```
# IP routing format
192.168.1.0/24 direct
10.0.0.0/8 proxy1:1080
...
```

### HTTP/TLS Traffic Routing

Run the HTTP/TLS aware proxy:

```bash
cd http-tls-routing
./http-router
```

### Comprehensive System

Run the integrated system with all features:

```bash
cd sum
go run .
```

Follow the on-screen menu to select the desired functionality.

## 🔧 Advanced Configuration

### TLS Certificate Generation

For TLS interception, generate certificates:

```bash
cd tls-hijack
go run -generate-cert
```

### Transparent Proxy Setup

To configure the transparent proxy mode:

```bash
sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 9768
sudo iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 9768
```

Then start the proxy in transparent mode.

## 📚 Documentation

Each module contains detailed documentation in the source code. For more information about specific components:

- SOCKS5 Protocol: [RFC 1928](https://tools.ietf.org/html/rfc1928)
- HTTP Protocol: [RFC 2616](https://tools.ietf.org/html/rfc2616)
- TLS Protocol: [RFC 8446](https://tools.ietf.org/html/rfc8446)

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ✨ Acknowledgements

- [Golang](https://golang.org/) - The programming language used
- [RFC 1928](https://tools.ietf.org/html/rfc1928) - SOCKS Protocol Version 5
