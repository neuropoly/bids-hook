package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/google/uuid"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var (
	// 127.0.0.1 is localhost, and 2845 is 0xB1D
	// this should be entered as-is in Gitea to configure the webhook
	bidsHookUrl = urlMustParse("http://127.0.0.1:2845/bids-hook")

	// secret used to authenticate api calls from Gitea to bids-hook
	bidsHookSecret = []byte("blabla")

	// json field validation patterns
	fullnamePattern = regexp.MustCompile(`^([0-9A-Za-z_.-]+)/([0-9A-Za-z_.-]+)$`)
	commitPattern   = regexp.MustCompile(`^([0-9a-f]{40})$`)
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

	// done with validation, now construct a job
	var job job

	// extract json fields from the request body
	// json structure taken from gitea/modules/structs/{hook,repo}.go
	var pushPayload struct {
		Repo struct {
			FullName string `json:"full_name"`
		} `json:"repository"`
		HeadCommit struct {
			ID string `json:"id"`
		} `json:"head_commit"`
	}
	err = json.Unmarshal(body, &pushPayload)
	if err != nil {
		log.Printf("postHandler: json error: %v", err)
		http.Error(w, "400 bad json", http.StatusBadRequest)
		return
	}
	match := fullnamePattern.FindStringSubmatch(pushPayload.Repo.FullName)
	if match == nil || match[1] == "." || match[1] == ".." || match[2] == "." || match[2] == ".." {
		log.Print("postHandler: bad repository.full_name")
		http.Error(w, "400 bad repository.full_name", http.StatusBadRequest)
		return
	}
	job.user = match[1]
	job.repo = match[2]
	match = commitPattern.FindStringSubmatch(pushPayload.HeadCommit.ID)
	if match == nil {
		log.Print("postHandler: bad head_commit.id")
		http.Error(w, "400 bad head_commit.id", http.StatusBadRequest)
		return
	}
	job.commit = match[1]

	// assign a fresh random uuid
	job.uuid, err = uuid.NewRandom()
	if err != nil {
		log.Printf("postHandler: uuid error: %v", err)
		http.Error(w, "500 error generating uuid", http.StatusInternalServerError)
		return
	}

	log.Printf("postHandler: got request %q %q %q %s", job.user, job.repo, job.commit, job.uuid)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusAccepted)
}

type job struct {
	// identifying info for the commit being bids-validated
	user   string
	repo   string
	commit string

	// unique and un-guessable identifier,
	// used for the filename/url of the generated results page
	uuid uuid.UUID
}
