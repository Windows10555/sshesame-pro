package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"path/filepath"
	"strings"
	"time"
)

type logEntry interface {
	fmt.Stringer
	eventType() string
}

type addressLog struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

func (entry addressLog) String() string {
	return net.JoinHostPort(entry.Host, fmt.Sprint(entry.Port))
}

func getAddressLog(host string, port int, cfg *config) interface{} {
	entry := addressLog{
		Host: host,
		Port: port,
	}
	if cfg.Logging.SplitHostPort {
		return entry
	}
	return entry.String()
}

type authAccepted bool

func (accepted authAccepted) String() string {
	if accepted {
		return "已允许"
	}
	return "已拒绝"
}

type authLog struct {
	User     string       `json:"accepted"`
	Accepted authAccepted `json:"rejected"`
}

type noAuthLog struct {
	authLog
}

func (entry noAuthLog) String() string {
	return fmt.Sprintf("以用户名 %q 不使用验证登录 %v", entry.User, entry.Accepted)
}
func (entry noAuthLog) eventType() string {
	return "no_auth"
}

type passwordAuthLog struct {
	authLog
	Password string `json:"password"`
}

func (entry passwordAuthLog) String() string {
	return fmt.Sprintf("以用户名 %q 附带密码 %q 登录 %v", entry.User, entry.Password, entry.Accepted)
}
func (entry passwordAuthLog) eventType() string {
	return "password_auth"
}

type publicKeyAuthLog struct {
	authLog
	PublicKeyFingerprint string `json:"public_key"`
}

func (entry publicKeyAuthLog) String() string {
	return fmt.Sprintf("以用户名 %q 带公钥 %q 登录 %v", entry.User, entry.PublicKeyFingerprint, entry.Accepted)
}
func (entry publicKeyAuthLog) eventType() string {
	return "public_key_auth"
}

type keyboardInteractiveAuthLog struct {
	authLog
	Answers []string `json:"answers"`
}

func (entry keyboardInteractiveAuthLog) String() string {
	return fmt.Sprintf("以用户名 %q with 使用输入验证的内容 %q 登录 %v", entry.User, entry.Answers, entry.Accepted)
}
func (entry keyboardInteractiveAuthLog) eventType() string {
	return "keyboard_interactive_auth"
}

type connectionLog struct {
	ClientVersion string `json:"client_version"`
}

func (entry connectionLog) String() string {
	return fmt.Sprintf("与客户端 %q 已连接", entry.ClientVersion)
}
func (entry connectionLog) eventType() string {
	return "connection"
}

type connectionCloseLog struct {
}

func (entry connectionCloseLog) String() string {
	return "连接被关闭"
}
func (entry connectionCloseLog) eventType() string {
	return "connection_close"
}

type tcpipForwardLog struct {
	Address interface{} `json:"address"`
}

func (entry tcpipForwardLog) String() string {
	return fmt.Sprintf("请求在 %v 上进行 TCP/IP 转发", entry.Address)
}
func (entry tcpipForwardLog) eventType() string {
	return "tcpip_forward"
}

type cancelTCPIPForwardLog struct {
	Address interface{} `json:"address"`
}

func (entry cancelTCPIPForwardLog) String() string {
	return fmt.Sprintf("在 %v 上的 TCP/IP 转发已取消", entry.Address)
}
func (entry cancelTCPIPForwardLog) eventType() string {
	return "cancel_tcpip_forward"
}

type noMoreSessionsLog struct {
}

func (entry noMoreSessionsLog) String() string {
	return "请求拒绝进一步的会话通道"
}
func (entry noMoreSessionsLog) eventType() string {
	return "no_more_sessions"
}

type hostKeysProveLog struct {
	HostKeyFiles []string `json:"host_key_files"`
}

func (entry hostKeysProveLog) String() string {
	baseNames := make([]string, len(entry.HostKeyFiles))
	for i, hostKeyFile := range entry.HostKeyFiles {
		baseNames[i] = fmt.Sprintf("%q", filepath.Base(hostKeyFile))
	}
	return fmt.Sprintf("请求主机密钥 %v 的所有权证明", strings.Join(baseNames, ", "))
}
func (entry hostKeysProveLog) eventType() string {
	return "host_keys_prove"
}

type channelLog struct {
	ChannelID int `json:"channel_id"`
}

type sessionLog struct {
	channelLog
}

func (entry sessionLog) String() string {
	return fmt.Sprintf("[通道 %v] 请求会话", entry.ChannelID)
}
func (entry sessionLog) eventType() string {
	return "session"
}

type sessionCloseLog struct {
	channelLog
}

func (entry sessionCloseLog) String() string {
	return fmt.Sprintf("[通道 %v] 已关闭", entry.ChannelID)
}
func (entry sessionCloseLog) eventType() string {
	return "session_close"
}

type sessionInputLog struct {
	channelLog
	Input string `json:"input"`
}

func (entry sessionInputLog) String() string {
	return fmt.Sprintf("[通道 %v] 输入：%q", entry.ChannelID, entry.Input)
}
func (entry sessionInputLog) eventType() string {
	return "session_input"
}

type directTCPIPLog struct {
	channelLog
	From interface{} `json:"from"`
	To   interface{} `json:"to"`
}

func (entry directTCPIPLog) String() string {
	return fmt.Sprintf("[通道 %v] 请求从 %v 到 %v 的直接 TCP/IP 转发", entry.ChannelID, entry.From, entry.To)
}
func (entry directTCPIPLog) eventType() string {
	return "direct_tcpip"
}

type directTCPIPCloseLog struct {
	channelLog
}

func (entry directTCPIPCloseLog) String() string {
	return fmt.Sprintf("[通道 %v] （直接 TCP/IP） 已关闭", entry.ChannelID)
}
func (entry directTCPIPCloseLog) eventType() string {
	return "direct_tcpip_close"
}

type directTCPIPInputLog struct {
	channelLog
	Input string `json:"input"`
}

func (entry directTCPIPInputLog) String() string {
	return fmt.Sprintf("[通道 %v] 输入（直接 TCP/IP）：%q", entry.ChannelID, entry.Input)
}
func (entry directTCPIPInputLog) eventType() string {
	return "direct_tcpip_input"
}

type ptyLog struct {
	channelLog
	Terminal string `json:"terminal"`
	Width    uint32 `json:"width"`
	Height   uint32 `json:"height"`
}

func (entry ptyLog) String() string {
	return fmt.Sprintf("[通道 %v] 请求使用终端 %q (尺寸 %vx%v) 的 PTY", entry.ChannelID, entry.Terminal, entry.Width, entry.Height)
}
func (entry ptyLog) eventType() string {
	return "pty"
}

type shellLog struct {
	channelLog
}

func (entry shellLog) String() string {
	return fmt.Sprintf("[通道 %v] 请求 Shell", entry.ChannelID)
}
func (entry shellLog) eventType() string {
	return "shell"
}

type execLog struct {
	channelLog
	Command string `json:"command"`
}

func (entry execLog) String() string {
	return fmt.Sprintf("[通道 %v] 请求命令 %q", entry.ChannelID, entry.Command)
}
func (entry execLog) eventType() string {
	return "exec"
}

type subsystemLog struct {
	channelLog
	Subsystem string `json:"subsystem"`
}

func (entry subsystemLog) String() string {
	return fmt.Sprintf("[通道 %v] 请求子系统 %q", entry.ChannelID, entry.Subsystem)
}
func (entry subsystemLog) eventType() string {
	return "subsystem"
}

type x11Log struct {
	channelLog
	Screen uint32 `json:"screen"`
}

func (entry x11Log) String() string {
	return fmt.Sprintf("[通道 %v] 请求屏幕 %v 上的 X11 转发", entry.ChannelID, entry.Screen)
}
func (entry x11Log) eventType() string {
	return "x11"
}

type envLog struct {
	channelLog
	Name  string `json:"name"`
	Value string `json:"value"`
}

func (entry envLog) String() string {
	return fmt.Sprintf("[通道 %v] 请求环境变量 %q，其值为 %q", entry.ChannelID, entry.Name, entry.Value)
}
func (entry envLog) eventType() string {
	return "env"
}

type windowChangeLog struct {
	channelLog
	Width  uint32 `json:"width"`
	Height uint32 `json:"height"`
}

func (entry windowChangeLog) String() string {
	return fmt.Sprintf("[通道 %v] 请求窗口尺寸更改为 %vx%v", entry.ChannelID, entry.Width, entry.Height)
}
func (entry windowChangeLog) eventType() string {
	return "window_change"
}

type debugGlobalRequestLog struct {
	RequestType string `json:"request_type"`
	WantReply   bool   `json:"want_reply"`
	Payload     string `json:"payload"`
}

func (entry debugGlobalRequestLog) String() string {
	jsonBytes, err := json.Marshal(entry)
	if err != nil {
		warningLogger.Printf("调试日志记录器：记录事件失败：%v", err)
		return ""
	}
	return fmt.Sprintf("DEBUG global request received: %v\n", string(jsonBytes))
}
func (entry debugGlobalRequestLog) eventType() string {
	return "debug_global_request"
}

type debugChannelLog struct {
	channelLog
	ChannelType string `json:"channel_type"`
	ExtraData   string `json:"extra_data"`
}

func (entry debugChannelLog) String() string {
	jsonBytes, err := json.Marshal(entry)
	if err != nil {
		warningLogger.Printf("调试日志记录器：记录事件失败：%v", err)
		return ""
	}
	return fmt.Sprintf("调试：请求新的通道：%v\n", string(jsonBytes))
}
func (entry debugChannelLog) eventType() string {
	return "debug_channel"
}

type debugChannelRequestLog struct {
	channelLog
	RequestType string `json:"request_type"`
	WantReply   bool   `json:"want_reply"`
	Payload     string `json:"payload"`
}

func (entry debugChannelRequestLog) String() string {
	jsonBytes, err := json.Marshal(entry)
	if err != nil {
		warningLogger.Printf("Failed to log event: %v", err)
		return ""
	}
	return fmt.Sprintf("调试：接收到通道请求：%v\n", string(jsonBytes))
}
func (entry debugChannelRequestLog) eventType() string {
	return "debug_channel_request"
}

func (context connContext) logEvent(entry logEntry) {
	if strings.HasPrefix(entry.eventType(), "debug_") && !context.cfg.Logging.Debug {
		return
	}
	if context.cfg.Logging.JSON {
		var jsonEntry interface{}
		tcpSource := context.RemoteAddr().(*net.TCPAddr)
		source := getAddressLog(tcpSource.IP.String(), tcpSource.Port, context.cfg)
		if context.cfg.Logging.Timestamps {
			jsonEntry = struct {
				Time      string      `json:"time"`
				Source    interface{} `json:"source"`
				EventType string      `json:"event_type"`
				Event     logEntry    `json:"event"`
			}{time.Now().Format(time.RFC3339), source, entry.eventType(), entry}
		} else {
			jsonEntry = struct {
				Source    interface{} `json:"source"`
				EventType string      `json:"event_type"`
				Event     logEntry    `json:"event"`
			}{source, entry.eventType(), entry}
		}
		logBytes, err := json.Marshal(jsonEntry)
		if err != nil {
			warningLogger.Printf("记录事件失败：%v", err)
			return
		}
		log.Print(string(logBytes))
	} else {
		log.Printf("[%v] %v", context.RemoteAddr().String(), entry)
	}
}
