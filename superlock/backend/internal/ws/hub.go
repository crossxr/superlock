package ws

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const (
	// writeWait bounds a single write to a stalled peer.
	writeWait = 10 * time.Second
	// pongWait is how long we tolerate silence before assuming the peer is gone.
	pongWait = 60 * time.Second
	// pingPeriod must be shorter than pongWait so a live peer always answers in
	// time.
	pingPeriod = (pongWait * 9) / 10
	// maxIncomingMessage caps what a client may send. Clients are not expected
	// to send anything at all.
	maxIncomingMessage = 1024
)

// checkOrigin permits a browser connection only from a configured origin.
//
// A request with no Origin header is not a browser — SDKs, the CLI and server
// processes do not send one — and is allowed through on the strength of its
// API token. Browser requests carry an Origin the page cannot forge, so
// matching it against the allowlist is what stops a hostile site from opening
// a socket with a token it somehow obtained.
func (h *Hub) checkOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	for _, allowed := range h.allowedOrigins {
		if allowed == "*" || strings.EqualFold(allowed, origin) {
			return true
		}
	}
	return false
}

type InvalidationEvent struct {
	Type      string `json:"type"` // "secret.updated" | "secret.deleted" | "secret.rotated"
	EnvID     string `json:"env_id"`
	SecretKey string `json:"secret_key,omitempty"`
}

type client struct {
	conn  *websocket.Conn
	envID string
	send  chan []byte
}

type Hub struct {
	mu             sync.RWMutex
	clients        map[string]map[*client]struct{} // envID -> set of clients
	allowedOrigins []string
}

// NewHub builds a hub. allowedOrigins should be the same list the HTTP CORS
// layer uses; an empty list permits only non-browser clients.
func NewHub(allowedOrigins []string) *Hub {
	cleaned := make([]string, 0, len(allowedOrigins))
	for _, o := range allowedOrigins {
		if o = strings.TrimSpace(o); o != "" {
			cleaned = append(cleaned, o)
		}
	}
	return &Hub{
		clients:        make(map[string]map[*client]struct{}),
		allowedOrigins: cleaned,
	}
}

func (h *Hub) register(c *client) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.clients[c.envID] == nil {
		h.clients[c.envID] = make(map[*client]struct{})
	}
	h.clients[c.envID][c] = struct{}{}
}

func (h *Hub) unregister(c *client) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if set, ok := h.clients[c.envID]; ok {
		delete(set, c)
		if len(set) == 0 {
			delete(h.clients, c.envID)
		}
	}
	close(c.send)
}

// Broadcast sends an invalidation event to all clients watching a given env.
//
// The read lock is held across the whole loop rather than just the map lookup.
// Releasing it early would leave two races against unregister, which holds the
// write lock while it both deletes from the map and closes the client's
// channel: iterating the live map as it is mutated, and sending on a channel
// that was closed in between. Either one crashes the process, and Broadcast is
// called from the rotation worker rather than an HTTP handler, so no recover
// middleware would catch it.
//
// Holding the lock is cheap because every send below is non-blocking.
func (h *Hub) Broadcast(envID string, event InvalidationEvent) {
	b, err := json.Marshal(event)
	if err != nil {
		return
	}

	h.mu.RLock()
	defer h.mu.RUnlock()

	for c := range h.clients[envID] {
		select {
		case c.send <- b:
		default:
			// slow client — drop this event rather than stall the broadcast
		}
	}
}

// ServeWS upgrades an HTTP connection and registers it with the hub for envID.
//
// The caller is responsible for authenticating the request and confirming that
// envID belongs to the caller's organization. This method performs no
// authorization of its own.
func (h *Hub) ServeWS(w http.ResponseWriter, r *http.Request, envID string) {
	upgrader := websocket.Upgrader{
		ReadBufferSize:  512,
		WriteBufferSize: 1024,
		CheckOrigin:     h.checkOrigin,
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	c := &client{conn: conn, envID: envID, send: make(chan []byte, 64)}
	h.register(c)
	defer h.unregister(c)

	// Write pump. The ping keeps intermediaries from idling the connection out
	// and, more importantly, gives the read pump something to fail on when the
	// peer is gone.
	go func() {
		ticker := time.NewTicker(pingPeriod)
		defer func() {
			ticker.Stop()
			conn.Close()
		}()
		for {
			select {
			case msg, ok := <-c.send:
				_ = conn.SetWriteDeadline(time.Now().Add(writeWait))
				if !ok {
					_ = conn.WriteMessage(websocket.CloseMessage, nil)
					return
				}
				if err := conn.WriteMessage(websocket.TextMessage, msg); err != nil {
					return
				}
			case <-ticker.C:
				_ = conn.SetWriteDeadline(time.Now().Add(writeWait))
				if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
					return
				}
			}
		}
	}()

	// Read pump. Clients send nothing; this exists to notice disconnects and to
	// refresh the read deadline on each pong. Without the deadline a peer that
	// vanishes without a FIN would hold the goroutine and its slot forever.
	conn.SetReadLimit(maxIncomingMessage)
	_ = conn.SetReadDeadline(time.Now().Add(pongWait))
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(pongWait))
	})
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			return
		}
	}
}
