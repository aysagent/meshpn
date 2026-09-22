// Local ECH test endpoints, standard library only (Go 1.24+).
// All keys/certificates/configs are ephemeral; stdout is bounded JSON metadata.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const outerName = "public.ech.test"
const innerName = "hidden.ech.test"

// Test-client teardown: after tls.Conn sends close_notify, drain the peer's
// remaining TLS records before closing TCP. Otherwise unread shutdown records
// can produce an RST in the relay after an already verified HTTP response.
// No application reads or handshake verification are bypassed by this cleanup.
type orderlyTCP struct {
	*net.TCPConn
	once sync.Once
	err  error
}

func (c *orderlyTCP) Close() error {
	c.once.Do(func() {
		_ = c.SetDeadline(time.Now().Add(time.Second))
		_ = c.CloseWrite()
		_, _ = io.Copy(io.Discard, io.LimitReader(c.TCPConn, 64*1024))
		c.err = c.TCPConn.Close()
	})
	return c.err
}

func must[T any](v T, err error) T {
	if err != nil {
		panic("ECH fixture setup failed")
	}
	return v
}

func vector(b []byte) []byte {
	out := binary.BigEndian.AppendUint16(nil, uint16(len(b)))
	return append(out, b...)
}

// RFC 9849 ECHConfig: X25519 / HKDF-SHA256 / AES-128-GCM. No HPKE
// implementation here: crypto/tls performs real encryption and verification.
func echKey(id byte) tls.EncryptedClientHelloKey {
	key := must(ecdh.X25519().GenerateKey(rand.Reader))
	contents := []byte{id, 0, 0x20}
	contents = append(contents, vector(key.PublicKey().Bytes())...)
	contents = append(contents, vector([]byte{0, 1, 0, 1})...)
	contents = append(contents, 64, byte(len(outerName)))
	contents = append(contents, outerName...)
	contents = append(contents, 0, 0) // empty extensions
	config := append([]byte{0xfe, 0x0d}, vector(contents)...)
	return tls.EncryptedClientHelloKey{Config: config, PrivateKey: key.Bytes(), SendAsRetry: true}
}

func certificate(names []string) (tls.Certificate, *x509.CertPool) {
	key := must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER := must(x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key))
	ca = must(x509.ParseCertificate(caDER))
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: names,
		NotBefore: ca.NotBefore, NotAfter: ca.NotAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER := must(x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, key))
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: key}, pool
}

type command struct {
	Port int    `json:"port"`
	HTTP string `json:"http"`
	Mode string `json:"mode"`
}

func main() {
	if len(os.Args) != 2 {
		return
	}
	mode := os.Args[1]
	if mode != "accept" && mode != "hrr" && mode != "unsupported" && mode != "bad-inner" && mode != "bad-outer" {
		return
	}
	names := []string{outerName, innerName}
	if mode == "bad-inner" {
		names = []string{outerName}
	}
	if mode == "bad-outer" {
		names = []string{innerName}
	}
	cert, roots := certificate(names)
	current, stale := echKey(1), echKey(2)
	serverTLS := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519},
		EncryptedClientHelloKeys: []tls.EncryptedClientHelloKey{current}}
	if mode == "hrr" {
		serverTLS.CurvePreferences = []tls.CurveID{tls.CurveP256}
	}
	if mode == "unsupported" {
		serverTLS.EncryptedClientHelloKeys = nil
	}
	var requests atomic.Int64
	server := &http.Server{TLSConfig: serverTLS, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 5 * time.Second,
		ErrorLog: log.New(io.Discard, "", 0),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests.Add(1)
			body, err := io.ReadAll(io.LimitReader(r.Body, 64*1024+1))
			if err != nil || len(body) > 64*1024 {
				http.Error(w, "body limit", 413)
				return
			}
			hash := sha256.Sum256(body)
			_ = json.NewEncoder(w).Encode(map[string]any{"echAccepted": r.TLS.ECHAccepted,
				"serverName": r.TLS.ServerName, "http": r.Proto, "resumed": r.TLS.DidResume,
				"bytes": len(body), "sha256": hex.EncodeToString(hash[:])})
		})}
	listener := must(net.Listen("tcp4", "127.0.0.1:0"))
	defer server.Close()
	go func() { _ = server.ServeTLS(listener, "", "") }()
	output := json.NewEncoder(os.Stdout)
	_ = output.Encode(map[string]any{"ready": true, "port": listener.Addr().(*net.TCPAddr).Port})
	cache := tls.NewLRUClientSessionCache(8)
	var retry []byte
	input := bufio.NewScanner(os.Stdin)
	input.Buffer(make([]byte, 4096), 4096)
	for input.Scan() {
		var cmd command
		if json.Unmarshal(input.Bytes(), &cmd) != nil || cmd.Port < 1024 || cmd.Port > 65535 ||
			(cmd.HTTP != "1.1" && cmd.HTTP != "2") {
			return
		}
		configList := vector(current.Config)
		switch cmd.Mode {
		case "stale":
			configList = vector(stale.Config)
		case "retry":
			if len(retry) == 0 {
				_ = output.Encode(map[string]any{"error": "NO_RETRY_CONFIG"})
				continue
			}
			configList = bytes.Clone(retry)
		case "", "bad-ca":
		default:
			return
		}
		config := &tls.Config{RootCAs: roots, ServerName: innerName,
			MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
			CurvePreferences:               []tls.CurveID{tls.X25519, tls.CurveP256},
			EncryptedClientHelloConfigList: configList, ClientSessionCache: cache}
		if cmd.Mode == "bad-ca" {
			config.RootCAs = x509.NewCertPool()
		}
		transport := &http.Transport{TLSClientConfig: config, ForceAttemptHTTP2: cmd.HTTP == "2",
			DisableKeepAlives: true, TLSHandshakeTimeout: 5 * time.Second,
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp4", "127.0.0.1:"+strconv.Itoa(cmd.Port))
				if err != nil {
					return nil, err
				}
				return &orderlyTCP{TCPConn: conn.(*net.TCPConn)}, nil
			}}
		if cmd.HTTP == "1.1" {
			transport.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
		}
		payload := bytes.Repeat([]byte("ECH real application payload\n"), 1024)
		client := &http.Client{Transport: transport, Timeout: 8 * time.Second}
		response, err := client.Post("https://"+innerName+"/", "application/octet-stream", bytes.NewReader(payload))
		result := map[string]any{}
		retry = nil
		if err != nil {
			var rejection *tls.ECHRejectionError
			var hostname x509.HostnameError
			var authority x509.UnknownAuthorityError
			switch {
			case errors.As(err, &rejection):
				retry = bytes.Clone(rejection.RetryConfigList)
				result["error"] = "ECH_REJECTED"
				result["retryAvailable"] = len(retry) > 0
			case errors.As(err, &hostname):
				result["error"] = "CERT_HOSTNAME"
			case errors.As(err, &authority):
				result["error"] = "CERT_AUTHORITY"
			default:
				result["error"] = "TLS_OR_HTTP_ERROR"
			}
		} else {
			body, readErr := io.ReadAll(io.LimitReader(response.Body, 8192))
			_ = response.Body.Close()
			if readErr != nil || response.StatusCode != 200 || json.Unmarshal(body, &result) != nil {
				return
			}
			result["clientECH"] = response.TLS.ECHAccepted
			result["clientResumed"] = response.TLS.DidResume
			result["verified"] = len(response.TLS.VerifiedChains) > 0
		}
		transport.CloseIdleConnections()
		result["requests"] = requests.Load()
		_ = output.Encode(result)
	}
}
