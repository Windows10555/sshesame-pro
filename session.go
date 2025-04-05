package main

import (
	"bufio"
	"errors"
	"io"
	"strings"
	"net"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

// --- Payload Structs and Methods (No changes needed here, keeping original structure) ---
//     So you can change it as original resp, may there have some problem

type ptyRequestPayload struct {
	Term                                   string
	Width, Height, PixelWidth, PixelHeight uint32
	Modes                                  string
}

func (request ptyRequestPayload) reply() []byte {
	return nil
}
func (request ptyRequestPayload) logEntry(channelID int) logEntry {
	return ptyLog{
		channelLog: channelLog{
			ChannelID: channelID,
		},
		Terminal: request.Term,
		Width:    request.Width,
		Height:   request.Height,
	}
}

type shellRequestPayload struct{}

func (request shellRequestPayload) reply() []byte {
	return nil
}
func (request shellRequestPayload) logEntry(channelID int) logEntry {
	return shellLog{
		channelLog: channelLog{
			ChannelID: channelID,
		},
	}
}

type x11RequestPayload struct {
	SingleConnection         bool
	AuthProtocol, AuthCookie string
	ScreenNumber             uint32
}

func (request x11RequestPayload) reply() []byte {
	return nil
}
func (request x11RequestPayload) logEntry(channelID int) logEntry {
	return x11Log{
		channelLog: channelLog{
			ChannelID: channelID,
		},
		Screen: request.ScreenNumber,
	}
}

type envRequestPayload struct {
	Name, Value string
}

func (request envRequestPayload) reply() []byte {
	return nil
}
func (request envRequestPayload) logEntry(channelID int) logEntry {
	return envLog{
		channelLog: channelLog{
			ChannelID: channelID,
		},
		Name:  request.Name,
		Value: request.Value,
	}
}

type execRequestPayload struct {
	Command string
}

func (request execRequestPayload) reply() []byte {
	return nil
}
func (request execRequestPayload) logEntry(channelID int) logEntry {
	return execLog{
		channelLog: channelLog{
			ChannelID: channelID,
		},
		Command: request.Command,
	}
}

type subsystemRequestPayload struct {
	Subsystem string
}

func (request subsystemRequestPayload) reply() []byte {
	return nil
}
func (request subsystemRequestPayload) logEntry(channelID int) logEntry {
	return subsystemLog{
		channelLog: channelLog{
			ChannelID: channelID,
		},
		Subsystem: request.Subsystem,
	}
}

type windowChangeRequestPayload struct {
	Width, Height, PixelWidth, PixelHeight uint32
}

func (request windowChangeRequestPayload) reply() []byte {
	return nil
}
func (request windowChangeRequestPayload) logEntry(channelID int) logEntry {
	return windowChangeLog{
		channelLog: channelLog{
			ChannelID: channelID,
		},
		Width:  request.Width,
		Height: request.Height,
	}
}

// --- Session Context and ReadLiners ---

type sessionContext struct {
	channelContext // Embed channelContext to access its fields like User(), RemoteAddr() etc.
	ssh.Channel
	inputChan chan string
	active    bool
	pty       bool
}

type scannerReadLiner struct {
	scanner   *bufio.Scanner
	inputChan chan<- string // Channel to send input back for logging
}

// ReadLine reads a line using the scanner and sends it to the input channel.
func (r scannerReadLiner) ReadLine() (string, error) {
	if !r.scanner.Scan() {
		if err := r.scanner.Err(); err != nil {
			return "", err // Return scanner error
		}
		return "", io.EOF // Return EOF if scanning is done
	}
	line := r.scanner.Text()
	// Send the read line to the logging channel
	// Use a non-blocking send or buffer the channel if necessary
	select {
	case r.inputChan <- line:
	default:
		// Handle case where channel is full or closed if needed
	}
	return line, nil
}

type terminalReadLiner struct {
	terminal  *term.Terminal
	inputChan chan<- string // Channel to send input back for logging
}

type clientEOFError struct{}

var clientEOF = clientEOFError{}

// Error returns the error message for client EOF.
func (clientEOFError) Error() string {
	return "客户端EOF" // Changed to Chinese
}

// ReadLine reads a line from the terminal and sends it to the input channel.
func (r terminalReadLiner) ReadLine() (string, error) {
	line, err := r.terminal.ReadLine()
	if err == nil || line != "" {
		// Send the read line to the logging channel
		// Use a non-blocking send or buffer the channel if necessary
		select {
		case r.inputChan <- line:
		default:
			// Handle case where channel is full or closed if needed
		}
	}
	if err == io.EOF {
		// Map io.EOF from terminal to our specific clientEOF error
		return line, clientEOF
	}
	return line, err
}

// --- Program Execution Handling ---

// handleProgram sets up the environment and executes the requested program (shell or command).
func (context *sessionContext) handleProgram(program []string) {
	context.active = true // Mark session as active
	var stdin readLiner
	var stdout, stderr io.Writer

	// Set up I/O based on whether a PTY was requested
	if context.pty {
		// Use terminal for I/O in PTY mode
		terminal := term.NewTerminal(context, "") // context itself implements io.ReadWriter
		stdin = terminalReadLiner{terminal, context.inputChan}
		stdout = terminal
		stderr = terminal
	} else {
		// Use standard channel I/O in non-PTY mode (e.g., exec)
		stdin = scannerReadLiner{bufio.NewScanner(context), context.inputChan}
		stdout = context          // Write stdout to the channel
		stderr = context.Stderr() // Write stderr to the channel's stderr pipe
	}

	// Execute the program in a separate goroutine
	go func() {
		// Ensure input channel is closed when the goroutine exits
		defer close(context.inputChan)

		// --- FIX: Added nil for cwd and context.RemoteAddr().String() for hostname ---
		// Extract remote address string safely
		remoteAddrStr := "unknown"
		if addr, ok := context.RemoteAddr().(*net.TCPAddr); ok {
			remoteAddrStr = addr.IP.String() // Use IP address as initial hostname
		} else {
			remoteAddrStr = context.RemoteAddr().String() // Fallback to full address string
		}


		// Execute the program using the commandContext
		result, err := executeProgram(commandContext{
			args:     program,
			stdin:    stdin,
			stdout:   stdout,
			stderr:   stderr,
			pty:      context.pty,
			user:     context.User(), // Get user from embedded channelContext
			cwd:      nil,            // cwd is managed internally by the shell command
			hostname: remoteAddrStr,  // Provide an initial hostname
		})

		// Log execution errors (excluding expected EOF types)
		if err != nil && err != io.EOF && err != clientEOF {
			warningLogger.Printf("执行程序时出错: %s", err) // Changed to Chinese
			// Consider sending an error status before returning
			// context.SendRequest("exit-status", false, ssh.Marshal(struct{ ExitStatus uint32 }{1})) // Example error status
			return
		}

		// Handle client EOF in PTY mode by sending CRLF for cleaner terminal output
		if err == clientEOF && context.pty {
			if _, writeErr := context.Write([]byte("\r\n")); writeErr != nil {
				warningLogger.Printf("发送CRLF时出错: %s", writeErr) // Changed to Chinese
				// Don't return here, still try to send exit status
			}
		}

		// Send the program's exit status back to the client
		exitStatusPayload := struct {
			ExitStatus uint32
		}{result}
		if _, sendErr := context.SendRequest("exit-status", false, ssh.Marshal(exitStatusPayload)); sendErr != nil {
			warningLogger.Printf("发送退出状态时出错: %s", sendErr) // Changed to Chinese
			// Don't return here, still try to close channel
		}

		// Send End-of-Write (EOW) for OpenSSH compatibility if needed
		if (context.pty && err == clientEOF) || err == nil {
			if _, sendErr := context.SendRequest("eow@openssh.com", false, nil); sendErr != nil {
				warningLogger.Printf("发送EOW时出错: %s", sendErr) // Changed to Chinese
				// Don't return here, still try to close channel
			}
		}

		// Close the write side of the channel to signal EOF to the client
		if closeErr := context.CloseWrite(); closeErr != nil {
			warningLogger.Printf("发送EOF时出错: %s", closeErr) // Changed to Chinese
		}

		// Close the channel completely
		if closeErr := context.Close(); closeErr != nil {
			warningLogger.Printf("关闭通道时出错: %s", closeErr) // Changed to Chinese
		}
	}()
}

// --- Request Handling ---

// handleRequest processes incoming SSH requests on the session channel.
func (context *sessionContext) handleRequest(request *ssh.Request) error {
	switch request.Type {
	case "pty-req":
		sessionChannelRequestsMetric.WithLabelValues(request.Type).Inc()
		if context.active {
			// PTY request must happen before shell/exec
			_ = request.Reply(false, nil) // Deny request
			return errors.New("pty请求必须在shell或exec之前") // Changed to Chinese
		}
		if context.pty {
			_ = request.Reply(false, nil) // Deny request
			return errors.New("已请求一个pty") // Changed to Chinese
		}
		payload := &ptyRequestPayload{}
		if err := ssh.Unmarshal(request.Payload, payload); err != nil {
			_ = request.Reply(false, nil) // Deny on bad payload
			return err
		}
		context.logEvent(payload.logEntry(context.channelID)) // Log PTY request
		if err := request.Reply(true, payload.reply()); err != nil {
			return err // Error sending reply
		}
		context.pty = true // Mark PTY as active for this session
		return nil

	case "shell":
		sessionChannelRequestsMetric.WithLabelValues(request.Type).Inc()
		if context.active {
			_ = request.Reply(false, nil) // Deny request
			return errors.New("会话已激活") // Changed to Chinese
		}
		if len(request.Payload) != 0 {
			_ = request.Reply(false, nil) // Deny request
			return errors.New("无效的请求负载") // Changed to Chinese
		}
		payload := &shellRequestPayload{}
		context.logEvent(payload.logEntry(context.channelID)) // Log shell request
		if err := request.Reply(true, payload.reply()); err != nil {
			return err // Error sending reply
		}
		context.handleProgram(shellProgram) // Start the default shell
		return nil

	case "exec":
		sessionChannelRequestsMetric.WithLabelValues(request.Type).Inc()
		if context.active {
			_ = request.Reply(false, nil) // Deny request
			return errors.New("会话已激活") // Changed to Chinese
		}
		payload := &execRequestPayload{}
		if err := ssh.Unmarshal(request.Payload, payload); err != nil {
			_ = request.Reply(false, nil) // Deny on bad payload
			return err
		}
		context.logEvent(payload.logEntry(context.channelID)) // Log exec request
		if err := request.Reply(true, payload.reply()); err != nil {
			return err // Error sending reply
		}
		program := strings.Fields(payload.Command) // Basic command parsing
		if len(program) == 0 {
			// Handle empty command if necessary, maybe exit with status 0?
			// For now, just close the channel gracefully.
			go func() {
				defer close(context.inputChan)
				exitStatusPayload := struct{ ExitStatus uint32 }{0}
				_, _ = context.SendRequest("exit-status", false, ssh.Marshal(exitStatusPayload))
				_ = context.CloseWrite()
				_ = context.Close()
			}()
		} else {
			context.handleProgram(program) // Execute the specified command
		}
		return nil

	case "env":
		sessionChannelRequestsMetric.WithLabelValues(request.Type).Inc()
		if context.active {
			_ = request.Reply(false, nil) // Deny request
			// Environment variables should be set before shell/exec
			return errors.New("环境变量必须在shell或exec之前设置") // Changed to Chinese
		}
		payload := &envRequestPayload{}
		if err := ssh.Unmarshal(request.Payload, payload); err != nil {
			_ = request.Reply(false, nil) // Deny on bad payload
			return err
		}
		context.logEvent(payload.logEntry(context.channelID)) // Log env request
		// NOTE: Environment variables are logged but not actually used by executeProgram in this example.
		// A real implementation would store these and pass them to the execution environment.
		return request.Reply(true, payload.reply()) // Acknowledge env variable

	case "subsystem":
		sessionChannelRequestsMetric.WithLabelValues(request.Type).Inc()
		if context.active {
			_ = request.Reply(false, nil) // Deny request
			return errors.New("会话已激活") // Changed to Chinese
		}
		payload := &subsystemRequestPayload{}
		if err := ssh.Unmarshal(request.Payload, payload); err != nil {
			_ = request.Reply(false, nil) // Deny on bad payload
			return err
		}
		context.logEvent(payload.logEntry(context.channelID)) // Log subsystem request
		// Subsystems are not implemented in this example
		warningLogger.Printf("不支持的子系统请求: %s", payload.Subsystem) // Changed to Chinese
		return request.Reply(false, nil)                              // Deny subsystem request

	case "window-change":
		sessionChannelRequestsMetric.WithLabelValues(request.Type).Inc()
		if !context.pty {
			// Window change only makes sense for PTY sessions
			_ = request.Reply(false, nil) // Deny request
			return errors.New("窗口更改仅适用于pty会话") // Changed to Chinese
		}
		payload := &windowChangeRequestPayload{}
		if err := ssh.Unmarshal(request.Payload, payload); err != nil {
			// Don't reply to window-change errors? Check RFC.
			return err
		}
		context.logEvent(payload.logEntry(context.channelID)) // Log window change
		// NOTE: Window size changes are logged but not acted upon in this example.
		// A real implementation would potentially resize the PTY.
		// No reply is sent for window-change requests according to RFC 4254 Section 6.7
		return nil

	case "x11-req":
		sessionChannelRequestsMetric.WithLabelValues(request.Type).Inc()
		// X11 forwarding not supported
		warningLogger.Println("不支持X11转发请求") // Changed to Chinese
		return request.Reply(false, nil)        // Deny X11 request

	case "signal":
		sessionChannelRequestsMetric.WithLabelValues(request.Type).Inc()
		// Signals not supported/handled in this simple example
		warningLogger.Println("不支持信号请求") // Changed to Chinese
		// No reply? Check RFC.
		return nil

	default:
		sessionChannelRequestsMetric.WithLabelValues("unknown").Inc()
		warningLogger.Printf("不支持的会话请求类型: %s", request.Type) // Changed to Chinese
		return request.Reply(false, nil)                           // Deny unknown requests
	}
}

// --- Main Session Channel Handler ---

var (
	sessionChannelsMetric = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sshesame_session_channels_total",
		Help: "Total number of session channels opened.",
	})
	activeSessionChannelsMetric = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "sshesame_active_session_channels",
		Help: "Number of currently active session channels.",
	})
	sessionChannelRequestsMetric = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sshesame_session_channel_requests_total",
		Help: "Total number of requests received on session channels.",
	}, []string{"type"})
)

// handleSessionChannel manages a single SSH session channel.
func handleSessionChannel(newChannel ssh.NewChannel, context channelContext) error {
	// Check if session limit is enforced (not used in this simplified version)
	if context.noMoreSessions {
		_ = newChannel.Reject(ssh.Prohibited, "已达到会话限制") // Changed to Chinese
		return errors.New("不应再请求更多会话")            // Changed to Chinese
	}
	// Basic validation of extra data (should be empty for session)
	if len(newChannel.ExtraData()) != 0 {
		_ = newChannel.Reject(ssh.ConnectionFailed, "无效的通道数据") // Changed to Chinese
		return errors.New("无效的通道数据")                     // Changed to Chinese
	}

	// Accept the channel request
	channel, requests, err := newChannel.Accept()
	if err != nil {
		// Log failure to accept channel
		warningLogger.Printf("无法接受会话通道 %d: %s", context.channelID, err) // Changed to Chinese
		return err
	}

	// Increment metrics and log channel opening
	sessionChannelsMetric.Inc()
	activeSessionChannelsMetric.Inc()
	defer activeSessionChannelsMetric.Dec() // Decrement active count when function returns

	context.logEvent(sessionLog{ // Log session start
		channelLog: channelLog{
			ChannelID: context.channelID,
		},
	})
	defer context.logEvent(sessionCloseLog{ // Log session close
		channelLog: channelLog{
			ChannelID: context.channelID,
		},
	})

	// Create the session context
	inputChan := make(chan string, 10) // Buffered channel for input logging
	session := sessionContext{context, channel, inputChan, false, false}

	// Main loop to handle requests and logged input
	for inputChan != nil || requests != nil {
		select {
		case input, ok := <-inputChan:
			if !ok {
				inputChan = nil // Goroutine exited, stop listening
				continue
			}
			// Log input received from the program execution context
			context.logEvent(sessionInputLog{
				channelLog: channelLog{
					ChannelID: context.channelID,
				},
				Input: input,
			})
		case request, ok := <-requests:
			if !ok {
				requests = nil // Request channel closed by SSH library
				// If the session wasn't activated (e.g., client closed before shell/exec),
				// ensure the inputChan is closed to terminate the potential logging select.
				if !session.active && inputChan != nil {
					// This case might be tricky if handleProgram hasn't started yet.
					// Consider using a shared flag or context cancellation.
					// For simplicity, try closing; handleProgram's defer will handle double close.
					// close(inputChan) // Be cautious with closing here.
				}
				continue // Stop listening for requests
			}

			// Log the raw request for debugging if needed
			context.logEvent(debugChannelRequestLog{
				channelLog: channelLog{
					ChannelID: context.channelID,
				},
				RequestType: request.Type,
				WantReply:   request.WantReply,
				Payload:     string(request.Payload), // Log payload as string
			})

			// Handle the specific request type
			if err := session.handleRequest(request); err != nil {
				// Log errors during request handling
				warningLogger.Printf("处理会话请求 %d (%s) 时出错: %s", context.channelID, request.Type, err) // Changed to Chinese
				// Decide if the error is fatal for the session
				// break // Example: break loop on critical error
			}
		}
	}

	// Session loop finished, resources are cleaned up by defers and goroutine exit
	return nil
}

