package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"regexp"
	"strings"
	"time"
)

const (
	statePending = "pending" // yellow dot
	stateSuccess = "success" // green checkmark
	stateFailure = "failure" // red "X" mark
	stateWarning = "warning" // yellow "!" mark
	stateError   = "error"   // red "!" mark
)

var (
	// 127.0.0.1 is localhost, and 2845 is 0xB1D
	// this should be entered as-is in Gitea to configure the webhook
	bidsHookUrl = urlMustParse("http://127.0.0.1:2845/bids-hook")

	// secret used to authenticate api calls from Gitea to bids-hook
	// this should be entered as-in in Gitea to configure the webhook
	bidsHookSecret = []byte("blabla")

	// the base URL to reach Gitea's API
	giteaApiUrl = urlMustParse("http://127.0.0.1:3000/api/v1")

	// secret used to authenticate api calls from bids-hook to Gitea
	// generated from a gitea admin account under "Settings" -> "Applications"
	giteaApiSecret = []byte("69e45fa9cfa75a7497633c6be8dd2347226e2f62")

	// the base URL for writing links to Gitea
	giteaPublicUrl = urlMustParse("http://127.0.0.1:3000/")

	// channel used to ferry jobs from the server to the worker
	jobs = make(chan job, 20)
	// channel used as a semaphore, to limit total jobs pending
	limiter = make(chan struct{}, cap(jobs))

	// executable run by the worker for each accepted job
	// the environment will contain the details of the job in
	// BH_USER, BH_REPO, BH_COMMIT, BH_UUID
	// the exit code will be used for the commit status posted to Gitea:
	// * 0 = "success" (green checkmark)
	// * 1 = "failure" (red "X" mark)
	// * 2 = "warning" (yellow "!" mark)
	workerScript = "./worker"

	// json field validation patterns
	fullnamePattern = regexp.MustCompile(`^([0-9A-Za-z_.-]+)/([0-9A-Za-z_.-]+)$`)
	commitPattern   = regexp.MustCompile(`^([0-9a-f]{40})$`)

	// random uuid (version 4, variant 1) validation pattern
	uuidPattern = regexp.MustCompile(`^([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$`)
)

func urlMustParse(rawURL string) *url.URL {
	u, err := url.Parse(rawURL)
	if err != nil {
		log.Fatal(err)
	}
	return u
}

func main() {
	log.Printf("main: starting worker")
	go worker()

	server := &http.Server{
		Addr:           bidsHookUrl.Host,
		Handler:        http.HandlerFunc(router),
		ReadTimeout:    1 * time.Second,
		WriteTimeout:   3 * time.Second,
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

	// extract the UUID generated by Gitea from the request headers
	match = uuidPattern.FindStringSubmatch(strings.ToLower(r.Header.Get("X-Gitea-Delivery")))
	if match == nil {
		log.Print("postHandler: bad uuid")
		http.Error(w, "400 bad uuid", http.StatusBadRequest)
		return
	}
	job.uuid = match[1]

	// reserve a spot in the job queue
	select {
	case limiter <- struct{}{}:
		// success, spot reserved
	default:
		log.Printf("postHandler: queue is full, refused job %q", job)
		w.Header().Set("Retry-After", "60")
		http.Error(w, "503 queue is full", http.StatusServiceUnavailable)
		return
	}
	// from this point on, all code paths should either:
	// * (success) send a job on the jobs channel to use the reserved spot, or
	// * (failure) receive from the limiter channel to free the reserved spot

	// post pending status on Gitea
	// (this doubles as a test that Gitea is reachable)
	err = job.postStatus(r.Context(), statePending)
	if err != nil {
		log.Printf("postHandler: error posting commit status: %v", err)
		http.Error(w, "500 error posting commit status", http.StatusInternalServerError)
		<-limiter // free the already reserved spot
		return
	}

	// send the job to the worker
	log.Printf("postHandler: accepted job %q", job)
	jobs <- job

	// reply to Gitea
	w.WriteHeader(http.StatusAccepted)
}

type job struct {
	// identifying info for the commit being bids-validated
	user   string
	repo   string
	commit string

	// random UUID generated by Gitea for this job,
	// used for the filename/url of the generated results page
	uuid string
}

// link to the results page for this job
func (j job) resultUrl() string {
	url := *giteaPublicUrl
	url.Path = path.Join(url.Path, "assets", fmt.Sprintf("%s.html", j.uuid))
	return url.String()
}

// postStatus posts a commit status to Gitea
// 'state' should be one of the constants defined at the top of this module
func (j job) postStatus(ctx context.Context, state string) error {
	url := *giteaApiUrl
	url.Path = path.Join(url.Path, "repos", j.user, j.repo, "statuses", j.commit)

	var description, targetUrl string
	switch state {
	case statePending:
		description = "waiting for results"
		targetUrl = ""
	case stateSuccess:
		description = "validation passed"
		targetUrl = j.resultUrl()
	case stateFailure:
		description = "validation failed"
		targetUrl = j.resultUrl()
	case stateWarning:
		description = "validation passed with warnings"
		targetUrl = j.resultUrl()
	case stateError:
		description = "internal error"
		targetUrl = ""
	}

	reqBody, err := json.Marshal(map[string]string{
		"context":     "bids-validator",
		"description": description,
		"state":       state,
		"target_url":  targetUrl,
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url.String(), bytes.NewReader(reqBody))
	if err != nil {
		return err
	}
	req.Header.Add("Authorization", fmt.Sprintf("token %s", giteaApiSecret))
	req.Header.Add("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	_, err = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if err != nil {
		return err
	}
	if resp.StatusCode > 299 {
		return errors.New(fmt.Sprintf("got http status code %d", resp.StatusCode))
	}

	return nil
}

func (j job) run() (state string, _ error) {
	cmd := exec.Command(workerScript)
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("BH_USER=%s", j.user),
		fmt.Sprintf("BH_REPO=%s", j.repo),
		fmt.Sprintf("BH_COMMIT=%s", j.commit),
		fmt.Sprintf("BH_UUID=%s", j.uuid),
	)
	err := cmd.Run()
	if err == nil {
		return stateSuccess, nil
	} else {
		if exitErr, ok := err.(*exec.ExitError); ok {
			switch exitErr.ExitCode() {
			case 1:
				return stateFailure, nil
			case 2:
				return stateWarning, nil
			default:
				return stateError, err
			}
		} else {
			return stateError, err
		}
	}
}

func worker() {
	for job := range jobs {
		log.Printf("worker: starting job %q", job)
		state, err := job.run()
		if err != nil {
			log.Printf("worker: error running job: %v", err)
		}
		ctx, done := context.WithTimeout(context.Background(), 3*time.Second)
		err = job.postStatus(ctx, state)
		done()
		if err != nil {
			log.Printf("worker: error posting commit status: %v", err)
		}
		log.Printf("worker: done with job %q", job)
		<-limiter
	}
}
