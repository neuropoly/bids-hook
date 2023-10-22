package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
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
	// url that bids-hook listens on
	// read from environment variable BIDS_HOOK_URL
	// this should be entered as-is in Gitea to configure the webhook
	bidsHookUrl *url.URL

	// secret used to authenticate api calls from Gitea to bids-hook
	// generated fresh on each startup
	bidsHookSecret []byte

	// the base URL to reach Gitea
	// read from environment variable GITEA_ROOT_URL
	// should match Gitea's app.ini's [server].ROOT_URL
	giteaRootUrl *url.URL

	// secret used to authenticate api calls from bids-hook to Gitea
	// read from environment variable GITEA_TOKEN
	// can be generated from a gitea admin account under "Settings" -> "Applications"
	giteaToken []byte

	// the path to Gitea's custom/ directory
	// read from environment variable GITEA_CUSTOM
	// used to save job result pages
	// see https://docs.gitea.io/en-us/config-cheat-sheet/#default-configuration-non-appini-configuration
	giteaCustom string

	// executable run by the worker for each accepted job
	// read from environment variable WORKER_SCRIPT
	// when called, the environment will contain the details of the job in
	// BH_USER, BH_REPO, BH_COMMIT, BH_UUID
	// the exit code will be used for the commit status posted to Gitea:
	// * 0 = "success" (green checkmark)
	// * 1 = "failure" (red "X" mark)
	// * 2 = "warning" (yellow "!" mark)
	// stdout will be saved to the Gitea url "/assets/${BH_UUID}.html" and linked from the commit status
	// stderr will be appended to the log file "{{workerLogPath}}/${BH_UUID}.log"
	workerScript string

	// the path to a log directory for worker stderr output
	// read from environment variable WORKER_LOG_PATH
	// it should already exist
	workerLogPath string

	// channel used to ferry jobs from the server to the worker
	// capacity read from environment variable WORKER_QUEUE_CAPACITY
	jobs chan job
	// channel used as a semaphore, to limit total jobs pending
	limiter chan struct{}

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
	log.Printf("main: reading config from environment")
	readConfig()

	log.Printf("main: starting worker")
	go worker()

	server := &http.Server{
		Addr:           bidsHookUrl.Host,
		Handler:        http.HandlerFunc(router),
		ReadTimeout:    1 * time.Second,
		WriteTimeout:   3 * time.Second,
		MaxHeaderBytes: 4 << 10,
	}
	addr := server.Addr
	if addr == "" {
		addr = ":http"
	}
	sock, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("main: listening on %q", bidsHookUrl)
	err = installWebhook()
	if err != nil {
		log.Fatalf("error installing webhook: %v", err)
	}
	log.Fatal(server.Serve(sock))
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

type Hook struct {
	ID                  int64             `json:"id"`
	Type                string            `json:"type"`
	URL                 string            `json:"-"`
	Config              map[string]string `json:"config"`
	Events              []string          `json:"events"`
	AuthorizationHeader string            `json:"authorization_header"`
	Active              bool              `json:"active"`
	IsSystemWebhook     bool              `json:"is_system_webhook"`
	Updated             time.Time         `json:"updated_at"`
	Created             time.Time         `json:"created_at"`
}

// set up the webhook
func installWebhook() error {
	url := giteaRootUrl.JoinPath("api", "v1", "admin", "hooks")

	_bidsHookSecret := make([]byte, 32)
	_, err := rand.Read(_bidsHookSecret)
	if err != nil {
		return err
	}
	// hex-encode, to avoid any trouble with unusual characters
	bidsHookSecret = make([]byte, hex.EncodedLen(len(_bidsHookSecret)))
	hex.Encode(bidsHookSecret, _bidsHookSecret)

	// This is the hook we want to exist
	// Note: Gitea internally uses a CreateHookOption or a EditHookOption for these
	//       which are two different subsets of the Hook type. So we're not being 100% correct here.
	log.Printf("SECERT: %s", string(bidsHookSecret))
	hook := Hook{
		Type: "gitea",
		Config: map[string]string{
			"content_type": "json",
			"url":          bidsHookUrl.String(),
			// notice: we *regenerate* the secret *each time*
			// it is entirely ephemeral, and thus we must always create/patch the hook
			"secret": string(bidsHookSecret),
		},
		Events:          []string{"push"},
		Active:          true,
		IsSystemWebhook: true,
	}

	hookJSON, err := json.Marshal(hook)
	if err != nil {
		return err
	}

	// Check if the hook already exists
	req, err := http.NewRequest(http.MethodGet, url.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Add("Authorization", fmt.Sprintf("token %s", giteaToken))
	req.Header.Add("Accept", "application/json")
	log.Printf("Calling %s %s\n", req.Method, url.String()) // DEBUG

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return errors.New(fmt.Sprintf("got http status code %d", resp.StatusCode))
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var hooks []Hook
	err = json.Unmarshal(body, &hooks)
	if err != nil {
		return err
	}
	fmt.Printf("Read this: |%s|\n", body)
	// search the result for pre-existing webhook
	found := false
	var id int64
	fmt.Printf("hook: %#v\n", hook) // DEBUG
	for _, _hook := range hooks {
		fmt.Printf("hook: %#v\n", _hook) // DEBUG
		if _hook.URL == hook.URL {
			fmt.Printf("found at id: %#v\n", _hook.ID) // DEBUG
			found = true
			id = _hook.ID
			break
		}
	}

	// depending on whether we found, either use POST or PATCH
	method := http.MethodPost
	if found {
		method = http.MethodPatch
		url = url.JoinPath(fmt.Sprintf("%d", id))
	}
	log.Printf("Calling %s %s\n", method, url.String()) // DEBUG

	req, err = http.NewRequest(method, url.String(), bytes.NewReader(hookJSON))
	if err != nil {
		return err
	}
	req.Header.Add("Authorization", fmt.Sprintf("token %s", giteaToken))
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/json")

	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		log.Printf("Bailing\n")
		return errors.New(fmt.Sprintf("got http status code %d", resp.StatusCode))
	}
	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	fmt.Printf("Read: |%s|\n", body)
	defer resp.Body.Close()

	return nil
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

// web link to the results page for this job
// see also j.resultPath()
func (j job) resultUrl() string {
	return giteaRootUrl.JoinPath("assets", "bids-validator", j.uuid[:2], j.uuid[2:4], fmt.Sprintf("%s.html", j.uuid)).String()
}

// file path to the results page for this job
// see also j.resultUrl()
func (j job) resultPath() string {
	return filepath.Join(giteaCustom, "public", "bids-validator", j.uuid[:2], j.uuid[2:4], fmt.Sprintf("%s.html", j.uuid))
}

// file path to the log file for this job
func (j job) logPath() string {
	return filepath.Join(workerLogPath, fmt.Sprintf("%s.log", j.uuid))
}

// postStatus posts a commit status to Gitea
// 'state' should be one of the constants defined at the top of this module
func (j job) postStatus(ctx context.Context, state string) error {
	url := giteaRootUrl.JoinPath("api", "v1", "repos", j.user, j.repo, "statuses", j.commit)

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
	req.Header.Add("Authorization", fmt.Sprintf("token %s", giteaToken))
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

	// redirect stdout to the result file
	resultPath := j.resultPath()
	err := os.MkdirAll(filepath.Dir(resultPath), 0750)
	if err != nil {
		return stateError, err
	}
	stdout, err := os.OpenFile(resultPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0640)
	if err != nil {
		return stateError, err
	}
	defer func() {
		err = stdout.Close()
		if err != nil {
			log.Printf("job.run: error closing stdout: %v", err)
		}
	}()
	cmd.Stdout = stdout

	// redirect stderr to the log file
	stderr, err := os.OpenFile(j.logPath(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return stateError, err
	}
	defer func() {
		err = stderr.Close()
		if err != nil {
			log.Printf("job.run: error closing stderr: %v", err)
		}
	}()
	cmd.Stderr = stderr

	// call the worker script and check its exit code
	err = cmd.Run()
	switch cmd.ProcessState.ExitCode() {
	case 0:
		return stateSuccess, nil
	case 1:
		return stateFailure, nil
	case 2:
		return stateWarning, nil
	default:
		return stateError, err
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

// readConfig sets up global variables from environment values
func readConfig() {
	var (
		val  string
		ok   bool
		err  error
		info fs.FileInfo
	)

	val, ok = os.LookupEnv("BIDS_HOOK_URL")
	if !ok {
		log.Fatal("missing environment variable BIDS_HOOK_URL")
	}
	bidsHookUrl, err = url.Parse(val)
	if err != nil {
		log.Fatalf("error parsing BIDS_HOOK_URL: %v", err)
	}

	val, ok = os.LookupEnv("GITEA_ROOT_URL")
	if !ok {
		log.Fatal("missing environment variable GITEA_ROOT_URL")
	}
	giteaRootUrl, err = url.Parse(val)
	if err != nil {
		log.Fatalf("error parsing GITEA_ROOT_URL: %v", err)
	}

	val, ok = os.LookupEnv("GITEA_TOKEN")
	if !ok {
		log.Fatal("missing environment variable GITEA_TOKEN")
	}
	giteaToken = []byte(val)

	val, ok = os.LookupEnv("GITEA_CUSTOM")
	if !ok {
		log.Fatal("missing environment variable GITEA_CUSTOM")
	}
	giteaCustom, err = filepath.Abs(val)
	if err != nil {
		log.Fatalf("invalid GITEA_CUSTOM: %v", err)
	}
	err = os.MkdirAll(filepath.Join(giteaCustom, "public", "bids-validator"), 0750)
	if err != nil {
		log.Fatalf("error creating output folder: %v", err)
	}

	val, ok = os.LookupEnv("WORKER_SCRIPT")
	if !ok {
		log.Fatal("missing environment variable WORKER_SCRIPT")
	}
	workerScript, err = exec.LookPath(val)
	if err != nil {
		log.Fatalf("invalid WORKER_SCRIPT: %v", err)
	}

	val, ok = os.LookupEnv("WORKER_LOG_PATH")
	if !ok {
		log.Fatal("missing environment variable WORKER_LOG_PATH")
	}
	workerLogPath, err = filepath.Abs(val)
	if err != nil {
		log.Fatalf("invalid WORKER_LOG_PATH: %v", err)
	}
	info, err = os.Stat(workerLogPath)
	if err != nil {
		log.Fatalf("error opening WORKER_LOG_PATH: %v", err)
	}
	if !info.IsDir() {
		log.Fatal("WORKER_LOG_PATH is not a directory")
	}

	val, ok = os.LookupEnv("WORKER_QUEUE_CAPACITY")
	if !ok {
		log.Fatal("missing environment variable WORKER_QUEUE_CAPACITY")
	}
	capacity, err := strconv.Atoi(val)
	if err != nil {
		log.Fatalf("error parsing WORKER_QUEUE_CAPACITY: %v", err)
	}
	jobs = make(chan job, capacity)
	limiter = make(chan struct{}, capacity)
}
