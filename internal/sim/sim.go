// Package sim — сетевой симулятор для тестов без живого сервера (docs/architecture.md §12.1):
// настоящий Xray-core с VLESS+REALITY+XHTTP на петле, сайт-маска TLS 1.3 и цель за тоннелем
// (204, загрузка N байт, загрузка с остановкой). Импортируется только тестами.
//
// REALITY сервера — XTLS/REALITY 8cdf7bf (как в Xray v26.9.9+): ClientHello без
// X25519MLKEM768 перед X25519 уходит маске — правило, на котором ломается Hiddify 4.x.
package sim

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"

	_ "github.com/xtls/xray-core/app/dispatcher"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	_ "github.com/xtls/xray-core/proxy/freedom"
	_ "github.com/xtls/xray-core/proxy/vless/inbound"
	_ "github.com/xtls/xray-core/transport/internet/reality"
	_ "github.com/xtls/xray-core/transport/internet/splithttp"
)

// Ключ сгенерирован для теста (как в tests/fixtures/doctor-hellos.json grokki91/xray) и ни на
// одном сервере не стоит. Адреса — петля, домен — example.com.
const (
	PrivateKey = "6Hwc0Wq52qtPrz13YitquD4MMKqlcG90DQSGCQDXs0w"
	UUID       = "00000000-0000-4000-8000-000000000001"
	SNI        = "www.example.com"
	Path       = "/xh-test"
	ShortID    = "0123abcd"
)

// Sim — запущенный стенд.
type Sim struct {
	Port      int    // порт REALITY на 127.0.0.1
	PublicKey string // pbk для профиля
	Target    string // host:port цели за тоннелем
	Mask      string // host:port сайта-маски
	closers   []func()
}

// Start поднимает маску, цель и сервер.
func Start() (*Sim, error) {
	s := &Sim{PublicKey: PublicKey()}
	var err error
	if s.Mask, err = s.mask(); err != nil {
		s.Close()
		return nil, err
	}
	if s.Target, err = s.target(); err != nil {
		s.Close()
		return nil, err
	}
	if s.Port, err = s.server(); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

// Close останавливает всё.
func (s *Sim) Close() {
	for i := len(s.closers) - 1; i >= 0; i-- {
		s.closers[i]()
	}
}

// URI — профиль на этот стенд.
func (s *Sim) URI(fp string) string {
	return fmt.Sprintf("vless://%s@127.0.0.1:%d?security=reality&sni=%s&fp=%s&pbk=%s&sid=%s&type=xhttp&path=%s&mode=auto#sim",
		UUID, s.Port, SNI, fp, s.PublicKey, ShortID, Path)
}

// URL — адрес цели за тоннелем.
func (s *Sim) URL(path string) string { return "http://" + s.Target + path }

// PublicKey — публичный ключ из тестового приватного.
func PublicKey() string {
	b, _ := base64.RawURLEncoding.DecodeString(PrivateKey)
	k, err := ecdh.X25519().NewPrivateKey(b)
	if err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(k.PublicKey().Bytes())
}

func (s *Sim) mask() (string, error) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: SNI}, DNSNames: []string{SNI},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return "", err
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion: tls.VersionTLS13, NextProtos: []string{"h2", "http/1.1"}})
	if err != nil {
		return "", err
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("<html>mask</html>")) }),
		ErrorLog: quietLog()}
	go srv.Serve(ln)
	s.closers = append(s.closers, func() { srv.Close() })
	return ln.Addr().String(), nil
}

func (s *Sim) target() (string, error) {
	mux := http.NewServeMux()
	mux.HandleFunc("/generate_204", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux.HandleFunc("/down", func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(r.URL.Query().Get("bytes"))
		_, _ = w.Write(make([]byte, n))
	})
	mux.HandleFunc("/stall", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "65536")
		_, _ = w.Write(make([]byte, 4000))
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
		case <-time.After(30 * time.Second):
		}
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	s.closers = append(s.closers, func() { srv.Close() })
	return ln.Addr().String(), nil
}

func (s *Sim) server() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	cfg := map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{
			"listen": "127.0.0.1", "port": port, "protocol": "vless",
			"settings": map[string]any{"clients": []any{map[string]any{"id": UUID}}, "decryption": "none"},
			"streamSettings": map[string]any{"network": "xhttp", "security": "reality",
				"realitySettings": map[string]any{"dest": s.Mask, "serverNames": []string{SNI}, "privateKey": PrivateKey, "shortIds": []string{ShortID}},
				"xhttpSettings":   map[string]any{"path": Path}},
		}},
		// Цель — на петле, а freedom по умолчанию петлю и частные сети блокирует.
		"outbounds": []any{map[string]any{"protocol": "freedom", "settings": map[string]any{"finalRules": []any{map[string]any{"action": "allow"}}}}},
	}
	b, _ := json.Marshal(cfg)
	jc, err := serial.DecodeJSONConfig(strings.NewReader(string(b)))
	if err != nil {
		return 0, err
	}
	cc, err := jc.Build()
	if err != nil {
		return 0, err
	}
	inst, err := core.New(cc)
	if err != nil {
		return 0, err
	}
	if err := inst.Start(); err != nil {
		return 0, err
	}
	s.closers = append(s.closers, func() { inst.Close() })
	return port, nil
}
