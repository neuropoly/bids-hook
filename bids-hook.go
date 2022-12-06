package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var (
	// 127.0.0.1 is localhost, and 2845 is 0xB1D
	// this should be entered as-is in Gitea to configure the webhook
	bidsHookUrl = urlMustParse("http://127.0.0.1:2845/bids-hook")

	// secret used to authenticate api calls from Gitea to bids-hook
	bidsHookSecret = []byte("blabla")
)

func urlMustParse(rawURL string) *url.URL {
	u, err := url.Parse(rawURL)
	if err != nil {
		log.Fatal(err)
	}
	return u
}

func main() {
	server := &http.Server{
		Addr:           bidsHookUrl.Host,
		Handler:        http.HandlerFunc(router),
		ReadTimeout:    1 * time.Second,
		MaxHeaderBytes: 4 << 10,
	}
	log.Printf("main: listening on %q", bidsHookUrl)
	log.Fatal(server.ListenAndServe())
}

// router checks the host, method and target of the request,
// and delegates meaningful requests to postHandler.
func router(w http.ResponseWriter, r *http.Request) {
	if host := r.Host; host != bidsHookUrl.Host {
		log.Printf("router: wrong host: %q", host)
		http.Error(w, "421 wrong host", http.StatusMisdirectedRequest)
		return
	}
	method := r.Method
	target := r.RequestURI
	log.Printf("router: got request for %q %q", method, target)
	switch method {
	case http.MethodPost:
		if target == bidsHookUrl.RequestURI() {
			postHandler(w, r)
			return
		}
	case http.MethodGet, http.MethodHead:
		if target == bidsHookUrl.RequestURI() {
			w.WriteHeader(http.StatusNoContent)
			return
		}
	case http.MethodOptions:
		if target == bidsHookUrl.RequestURI() {
			w.Header().Set("Allow", strings.Join([]string{
				http.MethodGet,
				http.MethodHead,
				http.MethodPost,
				http.MethodOptions,
			}, ", "))
			w.WriteHeader(http.StatusNoContent)
			return
		}
	default:
		http.Error(w, "501 wrong method", http.StatusNotImplemented)
		return
	}
	http.Error(w, "404 not found", http.StatusNotFound)
	return
}

// postHandler deals with requests that have successfully passed
// through the router based on their host, method and target.
func postHandler(w http.ResponseWriter, r *http.Request) {
	// see https://docs.gitea.io/en-us/webhooks/ for the validation steps
	// validate request: media type
	if mediaType := strings.ToLower(r.Header.Get("Content-Type")); mediaType != "application/json" {
		log.Printf("postHandler: wrong media type: %q", mediaType)
		http.Error(w, "415 only application/json is supported", http.StatusUnsupportedMediaType)
		return
	}

	// validate request: check signature
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("postHandler: error reading body: %v", err)
		http.Error(w, "500 error reading body", http.StatusInternalServerError)
		return
	}
	receivedMAC, err := hex.DecodeString(r.Header.Get("X-Gitea-Signature"))
	if err != nil {
		log.Printf("postHandler: signature decoding error: %v", err)
		http.Error(w, "400 malformed signature", http.StatusBadRequest)
		return
	}
	mac := hmac.New(sha256.New, bidsHookSecret)
	mac.Write(body)
	expectedMAC := mac.Sum(nil)
	if !hmac.Equal(receivedMAC, expectedMAC) {
		log.Print("postHandler: bad signature")
		http.Error(w, "403 bad signature", http.StatusForbidden)
		return
	}

	// done with validation
	log.Println("postHandler: got request")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusAccepted)
}
