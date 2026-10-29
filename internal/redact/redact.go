// Package redact убирает из текста всё, что идентифицирует установку: адрес сервера, SNI,
// UUID, ключи REALITY, shortId, путь XHTTP, URL подписки, IP-адреса, имя пользователя Windows.
//
// Значения заменяются метками: известные секреты (зарегистрированные через Add) — по виду и
// HMAC-хэшу на соли сессии, остальное — по шаблонам. IP-адреса — буквами по сетям /24 и /48,
// как в xm doctor: одна сеть — одна буква в пределах сессии. Соль не сохраняется вместе с
// экспортом, поэтому хэши в экспорте необратимы и несопоставимы между сессиями.
package redact

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// Kind — вид секрета; определяет метку.
type Kind string

const (
	Server Kind = "server" // адрес сервера (IP или домен)
	SNI    Kind = "sni"    // домен-маска
	UUID   Kind = "uuid"
	Key    Kind = "key"  // публичный ключ REALITY (pbk/password)
	SID    Kind = "sid"  // shortId
	Path   Kind = "path" // путь XHTTP
	URL    Kind = "url"  // URL подписки и прочие ссылки
	Host   Kind = "host" // SSH-алиас, имя хоста
	Other  Kind = "secret"
)

// Redactor потокобезопасен; один на сессию диагностики.
type Redactor struct {
	salt []byte

	mu      sync.Mutex
	secrets map[string]Kind // точное значение → вид
	nets    map[string]string
	keep    map[string]bool // публичные хосты-эталоны, которые прятать незачем
}

// New создаёт редактор с солью; пустая соль — случайная.
func New(salt []byte) *Redactor {
	if len(salt) == 0 {
		salt = NewSalt()
	}
	return &Redactor{salt: salt, secrets: map[string]Kind{}, nets: map[string]string{}, keep: map[string]bool{}}
}

// NewSalt — 16 случайных байт.
func NewSalt() []byte {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return b
}

// Salt возвращает соль (для передачи серверу через мост — в hex).
func (r *Redactor) Salt() []byte { return append([]byte(nil), r.salt...) }

// SaltHex — соль в hex: 32 символа, формат xm bridge facts.
func (r *Redactor) SaltHex() string { return hex.EncodeToString(r.salt) }

// Hash — HMAC-SHA256(соль, v), первые 12 hex-символов. Пустое значение — пустой хэш.
func (r *Redactor) Hash(v string) string {
	return HashWith(r.salt, v)
}

// HashWith — тот же хэш с явной солью (сверка с выводом сервера).
func HashWith(salt []byte, v string) string {
	if v == "" {
		return ""
	}
	m := hmac.New(sha256.New, salt)
	m.Write([]byte(v))
	return hex.EncodeToString(m.Sum(nil))[:12]
}

// Add регистрирует секрет: дальше любое его вхождение в тексте заменяется меткой.
// Значения короче 4 символов не регистрируются — их нельзя искать без ложных срабатываний.
func (r *Redactor) Add(kind Kind, value string) {
	value = strings.TrimSpace(value)
	if len(value) < 4 {
		return
	}
	r.mu.Lock()
	r.secrets[value] = kind
	// Путь XHTTP часто встречается без ведущего слэша или в URL-кодировке.
	if kind == Path {
		if t := strings.Trim(value, "/"); len(t) >= 4 {
			r.secrets[t] = kind
		}
		if e := strings.ReplaceAll(value, "/", "%2F"); e != value {
			r.secrets[e] = kind
		}
	}
	r.mu.Unlock()
}

// Keep помечает публичный хост, который не прячется (эталонные хосты: gstatic.com и т. п.).
func (r *Redactor) Keep(host string) {
	r.mu.Lock()
	r.keep[strings.ToLower(host)] = true
	r.mu.Unlock()
}

// Label — метка для секрета вида kind.
func (r *Redactor) Label(kind Kind, value string) string {
	switch kind {
	case Server:
		return "[server]"
	case SNI:
		return "[sni]"
	case Host:
		return "[host]"
	}
	return "[" + string(kind) + ":" + r.Hash(value)[:6] + "]"
}

var (
	reURI   = regexp.MustCompile(`(?i)\b(?:vless|vmess|trojan|ss|ssr|hysteria2|hy2|tuic|wireguard|socks|sub)://[^\s"'<>\x60]+`)
	reURL   = regexp.MustCompile(`(?i)\bhttps?://[^\s"'<>\x60]+`)
	reUUID  = regexp.MustCompile(`\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b`)
	reKey   = regexp.MustCompile(`\b[A-Za-z0-9_-]{43}\b`)
	reIPv4  = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	reIPv6  = regexp.MustCompile(`(?i)\[?\b[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}(?:%[0-9a-z]+)?\b\]?`)
	reUser  = regexp.MustCompile(`(?i)([a-z]:\\users\\)([^\\/\s"']+)`)
	reUserU = regexp.MustCompile(`(/home/|/Users/)([^/\s"']+)`)
)

// String возвращает текст без секретов.
func (r *Redactor) String(s string) string {
	if s == "" {
		return s
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	// 1. Известные секреты — длинные первыми, чтобы домен не съел часть URL раньше URL.
	vals := make([]string, 0, len(r.secrets))
	for v := range r.secrets {
		vals = append(vals, v)
	}
	sort.Slice(vals, func(i, j int) bool { return len(vals[i]) > len(vals[j]) })
	// URI и URL целиком — до точечной замены, иначе от URL останется хвост с параметрами.
	s = reURI.ReplaceAllStringFunc(s, func(m string) string { return "[uri:" + r.Hash(m)[:6] + "]" })
	s = reURL.ReplaceAllStringFunc(s, func(m string) string {
		if host := urlHost(m); host != "" && r.keep[strings.ToLower(host)] && !r.hasSecretLocked(m) {
			return m
		}
		return "[url:" + r.Hash(m)[:6] + "]"
	})
	for _, v := range vals {
		if strings.Contains(s, v) {
			s = strings.ReplaceAll(s, v, r.Label(r.secrets[v], v))
		}
	}
	// 2. Шаблоны.
	s = reUUID.ReplaceAllStringFunc(s, func(m string) string {
		return "[uuid:" + r.Hash(strings.ToLower(m))[:6] + "]"
	})
	s = reKey.ReplaceAllStringFunc(s, func(m string) string {
		if !looksLikeKey(m) {
			return m
		}
		return "[key:" + r.Hash(m)[:6] + "]"
	})
	s = reIPv4.ReplaceAllStringFunc(s, func(m string) string {
		a, err := netip.ParseAddr(m)
		if err != nil || !a.Is4() || keepAddr(a) {
			return m
		}
		return "[ip:" + r.netLetterLocked(a) + "]"
	})
	s = reIPv6.ReplaceAllStringFunc(s, func(m string) string {
		t := strings.Trim(m, "[]")
		if i := strings.IndexByte(t, '%'); i >= 0 {
			t = t[:i]
		}
		if strings.Count(t, ":") < 2 {
			return m
		}
		a, err := netip.ParseAddr(t)
		if err != nil || !a.Is6() || keepAddr(a) {
			return m
		}
		return "[ip:" + r.netLetterLocked(a) + "]"
	})
	s = reUser.ReplaceAllString(s, "${1}[user]")
	s = reUserU.ReplaceAllString(s, "${1}[user]")
	return s
}

func (r *Redactor) hasSecretLocked(s string) bool {
	for v := range r.secrets {
		if strings.Contains(s, v) {
			return true
		}
	}
	return false
}

// Strings — String для каждого элемента.
func (r *Redactor) Strings(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = r.String(s)
	}
	return out
}

// Any обходит значение из JSON (map/slice/string) и редактирует все строки, включая ключи.
func (r *Redactor) Any(v any) any {
	switch t := v.(type) {
	case string:
		return r.String(t)
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = r.Any(x)
		}
		return out
	case []string:
		return r.Strings(t)
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[r.String(k)] = r.Any(x)
		}
		return out
	default:
		return v
	}
}

// IPLetter — буква сети адреса (для улик: «сеть A»).
func (r *Redactor) IPLetter(a netip.Addr) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.netLetterLocked(a)
}

func (r *Redactor) netLetterLocked(a netip.Addr) string {
	var key string
	if a.Is4() || a.Is4In6() {
		b := a.Unmap().As4()
		key = string(b[:3])
	} else {
		b := a.As16()
		key = string(b[:6])
	}
	if l, ok := r.nets[key]; ok {
		return l
	}
	n := len(r.nets)
	l := string(rune('A' + n%26))
	if n >= 26 {
		l += string(rune('0' + n/26))
	}
	r.nets[key] = l
	return l
}

func keepAddr(a netip.Addr) bool {
	return a.IsLoopback() || a.IsUnspecified()
}

// looksLikeKey: 43 символа base64url — ключ x25519, если есть и цифры, и буквы разного регистра.
func looksLikeKey(s string) bool {
	var d, u, l bool
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9':
			d = true
		case c >= 'A' && c <= 'Z':
			u = true
		case c >= 'a' && c <= 'z':
			l = true
		}
	}
	return (d && u) || (d && l) || (u && l && strings.ContainsAny(s, "_-"))
}

func urlHost(u string) string {
	i := strings.Index(u, "://")
	if i < 0 {
		return ""
	}
	h := u[i+3:]
	if j := strings.IndexAny(h, "/?#"); j >= 0 {
		h = h[:j]
	}
	if j := strings.LastIndexByte(h, '@'); j >= 0 {
		h = h[j+1:]
	}
	if strings.HasPrefix(h, "[") {
		if j := strings.IndexByte(h, ']'); j >= 0 {
			return h[1:j]
		}
	}
	if j := strings.LastIndexByte(h, ':'); j >= 0 {
		h = h[:j]
	}
	return h
}

// Leaks ищет в тексте то, что не должно было остаться после редактирования: IP вне петли,
// UUID, ключи, URI прокси. Пусто — утечек нет. Используется тестами и проверкой экспорта.
func Leaks(s string) []string {
	var out []string
	for _, m := range reIPv4.FindAllString(s, -1) {
		if a, err := netip.ParseAddr(m); err == nil && a.Is4() && !keepAddr(a) {
			out = append(out, "ip "+m)
		}
	}
	for _, m := range reUUID.FindAllString(s, -1) {
		if !strings.HasPrefix(m, "00000000-0000-") {
			out = append(out, "uuid "+m)
		}
	}
	for _, m := range reKey.FindAllString(s, -1) {
		if looksLikeKey(m) {
			out = append(out, "key "+m)
		}
	}
	for _, m := range reURI.FindAllString(s, -1) {
		// Настоящий URI прокси — с «@» (vless://UUID@адрес); «vless://…» в подсказке — не он.
		if strings.Contains(m, "@") {
			out = append(out, "uri "+m)
		}
	}
	return out
}
