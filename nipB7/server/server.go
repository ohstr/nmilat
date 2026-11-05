package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ohstr/nmilat/nipB7"
)

// Options configure a Server. Store, PublicURL and at least one UploadPath
// are required.
type Options struct {
	// Store holds the blobs.
	Store Store
	// PublicURL is the origin blobs are served from, e.g.
	// "https://relay.example.com". Its host is the "server" an
	// authorization must name, and descriptor URLs start with it.
	PublicURL string
	// UploadPaths accept PUT uploads, e.g. "/upload".
	UploadPaths []string
	// BlobPrefix is the path blobs are served under: "/media" serves
	// /media/<sha256>[.ext]; "" serves /<sha256>[.ext].
	BlobPrefix string
	// MayUpload reports whether pubkey may upload. Nil allows anyone with a
	// valid authorization.
	MayUpload func(pubkey string) bool
	// MayDownload, when set, makes a download require a "get"
	// authorization whose signer it allows. Nil serves blobs to anyone.
	MayDownload func(pubkey string) bool
	// IsAdmin reports whether pubkey may delete any blob.
	IsAdmin func(pubkey string) bool
	// MaxBlobBytes caps one blob. 0 means 100 MiB.
	MaxBlobBytes int64
	// MaxUploadsPerSigner caps one signer's uploads in flight. 0 means 2.
	MaxUploadsPerSigner int
	// MaxUploads caps all uploads in flight. 0 means 8.
	MaxUploads int
	// TempDir holds uploads while they are hashed. "" means os.TempDir().
	TempDir string
}

// meta is the JSON document a Store keeps beside each blob.
type meta struct {
	Type     string   `json:"type,omitempty"`
	Size     int64    `json:"size"`
	Uploaded int64    `json:"uploaded"`
	Owners   []string `json:"owners"`
}

// Server serves Blossom over HTTP. Mount it with Register.
type Server struct {
	opt  Options
	host string

	slots chan struct{}

	mu       sync.Mutex
	inFlight map[string]int
	locks    map[string]*blobLock
}

// blobLock serializes one blob's metadata updates; n counts its holders and
// waiters, so the entry is dropped when nobody needs it.
type blobLock struct {
	mu sync.Mutex
	n  int
}

// New returns a Server for opt.
func New(opt Options) (*Server, error) {
	if opt.Store == nil {
		return nil, errors.New("blossom: Options.Store is required")
	}
	if len(opt.UploadPaths) == 0 {
		return nil, errors.New("blossom: Options.UploadPaths is required")
	}
	u, err := url.Parse(opt.PublicURL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("blossom: Options.PublicURL %q is not an absolute URL", opt.PublicURL)
	}
	opt.PublicURL = strings.TrimSuffix(opt.PublicURL, "/")
	opt.BlobPrefix = strings.TrimSuffix(opt.BlobPrefix, "/")
	if opt.MaxBlobBytes == 0 {
		opt.MaxBlobBytes = 100 << 20
	}
	if opt.MaxUploadsPerSigner == 0 {
		opt.MaxUploadsPerSigner = 2
	}
	if opt.MaxUploads == 0 {
		opt.MaxUploads = 8
	}
	return &Server{
		opt:      opt,
		host:     u.Host,
		slots:    make(chan struct{}, opt.MaxUploads),
		inFlight: make(map[string]int),
		locks:    make(map[string]*blobLock),
	}, nil
}

// Register mounts the server's routes on mux: PUT on each upload path,
// GET/HEAD/DELETE under the blob prefix, and OPTIONS (CORS) on both.
func (s *Server) Register(mux *http.ServeMux) {
	for _, p := range s.opt.UploadPaths {
		mux.HandleFunc("PUT "+p, s.cors(s.upload))
		mux.HandleFunc("OPTIONS "+p, s.cors(preflight))
	}
	prefix := s.opt.BlobPrefix + "/"
	mux.HandleFunc("GET "+prefix, s.cors(s.download))
	mux.HandleFunc("HEAD "+prefix, s.cors(s.download))
	mux.HandleFunc("DELETE "+prefix, s.cors(s.delete))
	mux.HandleFunc("OPTIONS "+prefix, s.cors(preflight))
}

// cors adds the headers BUD-01 asks every response to carry.
func (s *Server) cors(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Access-Control-Allow-Origin", "*")
		h.Set("Access-Control-Allow-Headers", "Authorization, *")
		h.Set("Access-Control-Allow-Methods", "GET, HEAD, PUT, DELETE")
		h.Set("Access-Control-Expose-Headers", "*")
		next(w, r)
	}
}

func preflight(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Access-Control-Max-Age", "86400")
	w.WriteHeader(http.StatusNoContent)
}

// blobPath matches a blob's path segment: a hash and an optional short
// extension.
var blobPath = regexp.MustCompile(`^([0-9a-f]{64})(\.[a-z0-9]{1,8})?$`)

// parseBlob returns the hash and extension r's path names, or ok false.
func (s *Server) parseBlob(r *http.Request) (sha, ext string, ok bool) {
	rest, found := strings.CutPrefix(r.URL.Path, s.opt.BlobPrefix+"/")
	if !found {
		return "", "", false
	}
	m := blobPath.FindStringSubmatch(rest)
	if m == nil {
		return "", "", false
	}
	return m[1], m[2], true
}

// authorize checks r's kind 24242 token for verb: signature, timing, verb,
// a "server" tag naming this host (required), and hash when given.
func (s *Server) authorize(r *http.Request, verb, hash string, requireHash bool) (*nipB7.Authorization, int, string) {
	auth, err := nipB7.VerifyAuthorization(r, nipB7.VerifyParams{Verb: verb, ServerHost: s.host, Hash: hash, RequireHash: requireHash})
	switch {
	case err == nil:
	case errors.Is(err, nipB7.ErrServerMismatch), errors.Is(err, nipB7.ErrHashNotAuthorized):
		return nil, http.StatusForbidden, err.Error()
	default:
		return nil, http.StatusUnauthorized, err.Error()
	}
	if len(auth.Servers) == 0 {
		return nil, http.StatusForbidden, "authorization must name this server"
	}
	return auth, 0, ""
}

// acquire takes an upload slot for pubkey, or reports false when the
// signer or the server is at its limit.
func (s *Server) acquire(pubkey string) bool {
	s.mu.Lock()
	if s.inFlight[pubkey] >= s.opt.MaxUploadsPerSigner {
		s.mu.Unlock()
		return false
	}
	s.inFlight[pubkey]++
	s.mu.Unlock()
	select {
	case s.slots <- struct{}{}:
		return true
	default:
		s.release(pubkey, false)
		return false
	}
}

func (s *Server) release(pubkey string, slot bool) {
	if slot {
		<-s.slots
	}
	s.mu.Lock()
	if s.inFlight[pubkey]--; s.inFlight[pubkey] <= 0 {
		delete(s.inFlight, pubkey)
	}
	s.mu.Unlock()
}

// lock serializes metadata updates for one blob.
func (s *Server) lock(sha string) func() {
	s.mu.Lock()
	l, ok := s.locks[sha]
	if !ok {
		l = &blobLock{}
		s.locks[sha] = l
	}
	l.n++
	s.mu.Unlock()
	l.mu.Lock()
	return func() {
		l.mu.Unlock()
		s.mu.Lock()
		if l.n--; l.n == 0 {
			delete(s.locks, sha)
		}
		s.mu.Unlock()
	}
}

func (s *Server) loadMeta(ctx context.Context, sha string) (*meta, error) {
	b, err := s.opt.Store.GetMeta(ctx, sha)
	if err != nil {
		return nil, err
	}
	var m meta
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

func (s *Server) saveMeta(ctx context.Context, sha string, m *meta) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return s.opt.Store.PutMeta(ctx, sha, b)
}

func (s *Server) descriptor(sha string, m *meta) nipB7.BlobDescriptor {
	return nipB7.BlobDescriptor{
		URL:      s.opt.PublicURL + s.opt.BlobPrefix + "/" + sha,
		Sha256:   sha,
		Size:     m.Size,
		Type:     m.Type,
		Uploaded: m.Uploaded,
	}
}

func (s *Server) upload(w http.ResponseWriter, r *http.Request) {
	auth, status, reason := s.authorize(r, nipB7.VerbUpload, "", false)
	if auth == nil {
		nipB7.WriteError(w, status, reason)
		return
	}
	if len(auth.Hashes) == 0 {
		nipB7.WriteError(w, http.StatusUnauthorized, "authorization must name the blob's hash (x tag)")
		return
	}
	if s.opt.MayUpload != nil && !s.opt.MayUpload(auth.PubKey) {
		nipB7.WriteError(w, http.StatusForbidden, "this key may not upload here")
		return
	}
	if r.ContentLength > s.opt.MaxBlobBytes {
		nipB7.WriteError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("blobs are limited to %d bytes", s.opt.MaxBlobBytes))
		return
	}
	if !s.acquire(auth.PubKey) {
		nipB7.WriteError(w, http.StatusTooManyRequests, "too many uploads in flight")
		return
	}
	defer s.release(auth.PubKey, true)

	tmp, err := os.CreateTemp(s.opt.TempDir, "blossom-upload-*")
	if err != nil {
		nipB7.WriteError(w, http.StatusInternalServerError, "could not stage upload")
		return
	}
	defer func() { _ = tmp.Close(); _ = os.Remove(tmp.Name()) }()

	h := sha256.New()
	size, err := io.Copy(io.MultiWriter(tmp, h), http.MaxBytesReader(w, r.Body, s.opt.MaxBlobBytes))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			nipB7.WriteError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("blobs are limited to %d bytes", s.opt.MaxBlobBytes))
			return
		}
		nipB7.WriteError(w, http.StatusBadRequest, "could not read upload")
		return
	}
	sha := hex.EncodeToString(h.Sum(nil))
	if want := r.Header.Get(nipB7.HeaderSHA256); want != "" && !strings.EqualFold(want, sha) {
		nipB7.WriteError(w, http.StatusBadRequest, "body does not match X-SHA-256")
		return
	}
	if !auth.HasHash(sha) {
		nipB7.WriteError(w, http.StatusForbidden, "authorization does not cover this blob's hash")
		return
	}

	unlock := s.lock(sha)
	defer unlock()

	m, err := s.loadMeta(r.Context(), sha)
	if errors.Is(err, ErrNotFound) {
		if _, err := tmp.Seek(0, io.SeekStart); err != nil {
			nipB7.WriteError(w, http.StatusInternalServerError, "could not store blob")
			return
		}
		ctype := r.Header.Get("Content-Type")
		if err := s.opt.Store.Put(r.Context(), sha, tmp, size, ctype); err != nil {
			nipB7.WriteError(w, http.StatusInternalServerError, "could not store blob")
			return
		}
		m = &meta{Type: ctype, Size: size, Uploaded: time.Now().Unix()}
	} else if err != nil {
		nipB7.WriteError(w, http.StatusInternalServerError, "could not read blob metadata")
		return
	}
	if !slices.Contains(m.Owners, auth.PubKey) {
		m.Owners = append(m.Owners, auth.PubKey)
	}
	if err := s.saveMeta(r.Context(), sha, m); err != nil {
		nipB7.WriteError(w, http.StatusInternalServerError, "could not store blob metadata")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.descriptor(sha, m))
}

func (s *Server) download(w http.ResponseWriter, r *http.Request) {
	sha, ext, ok := s.parseBlob(r)
	if !ok {
		nipB7.WriteError(w, http.StatusNotFound, "not a blob path")
		return
	}
	if s.opt.MayDownload != nil {
		auth, status, reason := s.authorize(r, nipB7.VerbGet, sha, false)
		if auth == nil {
			nipB7.WriteError(w, status, reason)
			return
		}
		if !s.opt.MayDownload(auth.PubKey) {
			nipB7.WriteError(w, http.StatusForbidden, "this key may not download here")
			return
		}
	}

	m, err := s.loadMeta(r.Context(), sha)
	if errors.Is(err, ErrNotFound) {
		nipB7.WriteError(w, http.StatusNotFound, "blob not found")
		return
	}
	if err != nil {
		nipB7.WriteError(w, http.StatusInternalServerError, "could not read blob metadata")
		return
	}
	blob, _, err := s.opt.Store.Open(r.Context(), sha)
	if errors.Is(err, ErrNotFound) {
		nipB7.WriteError(w, http.StatusNotFound, "blob not found")
		return
	}
	if err != nil {
		nipB7.WriteError(w, http.StatusInternalServerError, "could not open blob")
		return
	}
	defer func() { _ = blob.Close() }()

	if m.Type != "" {
		w.Header().Set("Content-Type", m.Type)
	}
	w.Header().Set("ETag", `"`+sha+`"`)
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	http.ServeContent(w, r, sha+ext, time.Unix(m.Uploaded, 0), blob)
}

func (s *Server) delete(w http.ResponseWriter, r *http.Request) {
	sha, _, ok := s.parseBlob(r)
	if !ok {
		nipB7.WriteError(w, http.StatusNotFound, "not a blob path")
		return
	}
	auth, status, reason := s.authorize(r, nipB7.VerbDelete, sha, true)
	if auth == nil {
		nipB7.WriteError(w, status, reason)
		return
	}

	unlock := s.lock(sha)
	defer unlock()

	m, err := s.loadMeta(r.Context(), sha)
	if errors.Is(err, ErrNotFound) {
		nipB7.WriteError(w, http.StatusNotFound, "blob not found")
		return
	}
	if err != nil {
		nipB7.WriteError(w, http.StatusInternalServerError, "could not read blob metadata")
		return
	}
	admin := s.opt.IsAdmin != nil && s.opt.IsAdmin(auth.PubKey)
	owner := slices.Contains(m.Owners, auth.PubKey)
	if !admin && !owner {
		nipB7.WriteError(w, http.StatusForbidden, "only an uploader or an admin may delete this blob")
		return
	}
	if owner && !admin {
		m.Owners = slices.DeleteFunc(m.Owners, func(pk string) bool { return pk == auth.PubKey })
	} else {
		m.Owners = nil
	}
	if len(m.Owners) > 0 {
		err = s.saveMeta(r.Context(), sha, m)
	} else {
		err = s.opt.Store.Delete(r.Context(), sha)
	}
	if err != nil {
		nipB7.WriteError(w, http.StatusInternalServerError, "could not delete blob")
		return
	}
	w.WriteHeader(http.StatusOK)
}
