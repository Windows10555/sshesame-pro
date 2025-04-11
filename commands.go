package main
import (
	"fmt"
	"io"
	"math/rand"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// --- 全局变量 ---
var globalHostname string // Stores the globally unique hostname

// --- 初始化函数 ---
func init() {
	// Initialize random number generator
	rand.Seed(time.Now().UnixNano())
	// Generate a one-time random hostname
	globalHostname = fmt.Sprintf("vm-%06d", rand.Intn(1000000))
}

// --- 接口定义 ---
type readLiner interface {
	ReadLine() (string, error)
}

type commandContext struct {
	args           []string
	stdin          readLiner
	stdout, stderr io.Writer
	pty            bool
	user           string
	cwd            *string // Pointer to current working directory (managed by shell)
	hostname       string  // Current session hostname
}

type command interface {
	execute(context commandContext) (uint32, error)
}

// --- 命令注册 ---
// commands stores all available commands and their implementations
var commands = map[string]command{
	"sh":       cmdShell{},
	"true":     cmdTrue{},
	"false":    cmdFalse{},
	"echo":     cmdEcho{},
	"cat":      cmdCat{},
	"su":       cmdSu{},
	"uname":    cmdUname{},
	"pwd":      cmdPwd{},
	"id":       cmdId{},
	"hostname": cmdHostname{},
	"cd":       cmdCd{},
	"exit":     cmdExit{},
	"wpm":      cmdWpm{}, // wpm 是一个假的类 apt ，用于迷惑攻击者
	"apt":      cmdApt{},
	"apt-get":  cmdAptGet{},
	"lscpu":    cmdLscpu{},  
	"free":     cmdFree{},   
	"lspci":    cmdLspci{},  
}

var shellProgram = []string{"sh"} // Default shell program

// --- 命令执行逻辑 ---
// executeProgram executes a command based on the context
func executeProgram(context commandContext) (uint32, error) {
	if len(context.args) == 0 {
		return 0, nil // No command, do nothing
	}
	command := commands[context.args[0]]
	if command == nil {
		// Command not found
		_, err := fmt.Fprintf(context.stderr, "%s: %v: 指令不存在\n", context.hostname, context.args[0])
		return 127, err // Standard exit code for command not found
	}
	// Execute the found command
	return command.execute(context)
}

// --- 命令实现 ---

// --- Shell (sh) 命令实现 ---
type cmdShell struct{}

func (cmdShell) execute(context commandContext) (uint32, error) {
	// Initialize shell state
	currentCwd := "/home/guest/" // Initial working directory
	currentHostname := globalHostname   // Use the globally generated hostname

	var lastStatus uint32 // Store the exit status of the last command
	var line string
	var err error

	for {
		// Build the prompt string: user@hostname:cwd$ or user@hostname:cwd#
		promptCwd := *(&currentCwd) // Get current cwd
		// Replace home directory path with ~
		homeDir := "/home/" + context.user
		if strings.HasPrefix(promptCwd, homeDir) {
			if promptCwd == homeDir {
				promptCwd = "~"
			} else {
				promptCwd = "~" + strings.TrimPrefix(promptCwd, homeDir)
			}
		}

		var promptSymbol = "$"
		if context.user == "root" {
			promptSymbol = "#"
		}
		prompt := fmt.Sprintf("%s@%s:%s%s ", context.user, currentHostname, promptCwd, promptSymbol)

		// Print prompt only in PTY environment
		if context.pty {
			_, err = fmt.Fprint(context.stdout, prompt)
			if err != nil {
				return lastStatus, err
			}
		}

		// Read user input
		line, err = context.stdin.ReadLine()
		if err != nil {
			// Handle EOF (Ctrl+D) gracefully
			if err == io.EOF {
				if context.pty { // Print "exit" only if in interactive mode
					fmt.Fprintln(context.stdout, "exit")
				}
				return lastStatus, nil // Normal exit
			}
			return lastStatus, err // Other read errors
		}

		// Parse command line arguments
		args := strings.Fields(line)
		if len(args) == 0 {
			continue // Ignore empty lines
		}

		// Create context for this command execution
		newContext := context
		newContext.args = args
		newContext.cwd = &currentCwd       // Pass pointer to current working directory
		newContext.hostname = currentHostname // Pass current hostname

		// Find and execute the command
		cmd := commands[args[0]]
		if cmd == nil {
			_, err = fmt.Fprintf(context.stderr, "%s: %v: 指令不存在\n", currentHostname, args[0])
			if err != nil {
				return 127, err // Return error if writing to stderr fails
			}
			lastStatus = 127 // Set last status for command not found
			continue
		}

		// Special handling for 'exit' command as it terminates the shell loop
		if args[0] == "exit" {
			exitStatus, _ := cmd.execute(newContext) // Execute exit command to get status code
			return exitStatus, nil                    // Exit the shell
		}

		// Execute other commands
		lastStatus, err = cmd.execute(newContext)
		if err != nil {
			// Errors during command execution (like write errors) are handled here
			fmt.Fprintf(context.stderr, "Shell execution error: %v\n", err)
			// Depending on the error, we might want to exit the shell
			// return lastStatus, err
		}
	}
}

// --- Exit 命令实现 ---
type cmdExit struct{}

func (cmdExit) execute(context commandContext) (uint32, error) {
	var status uint64 = 0 // Default exit code 0
	var err error
	if len(context.args) > 1 {
		status, err = strconv.ParseUint(context.args[1], 10, 32)
		if err != nil {
			// Invalid argument, POSIX shells typically return 255
			_, fmtErr := fmt.Fprintf(context.stderr, "%s: exit: %s: numeric argument required\n", context.hostname, context.args[1])
			return 255, fmtErr // Return 255 for argument error
		}
	}
	// Exit command itself shouldn't return an error, status code is passed via return value
	return uint32(status), nil
}

// --- True 命令实现 ---
type cmdTrue struct{}

func (cmdTrue) execute(context commandContext) (uint32, error) { return 0, nil }

// --- False 命令实现 ---
type cmdFalse struct{}

func (cmdFalse) execute(context commandContext) (uint32, error) { return 1, nil }

// --- Echo 命令实现 ---
type cmdEcho struct{}

func (cmdEcho) execute(context commandContext) (uint32, error) {
	_, err := fmt.Fprintln(context.stdout, strings.Join(context.args[1:], " "))
	if err != nil {
		return 1, err // Return 1 on output error
	}
	return 0, nil
}

// --- Cat 命令实现 ---
type cmdCat struct{}

func (cmdCat) execute(context commandContext) (uint32, error) {
	// Simplified cat: No file support, echoes stdin
	if len(context.args) > 1 {
		_, err := fmt.Fprintf(context.stderr, "%s: cat: 文件操作未实现\n", context.hostname)
		return 1, err // Return 1 for usage error/feature not implemented
	}
	// Read from stdin and write to stdout
	var line string
	var readErr error
	for readErr == nil {
		line, readErr = context.stdin.ReadLine()
		if readErr == nil {
			_, writeErr := fmt.Fprintln(context.stdout, line)
			if writeErr != nil {
				return 1, writeErr // Return 1 on write error
			}
		}
	}
	if readErr == io.EOF {
		return 0, nil // Normal termination
	}
	return 1, readErr // Return 1 on read error
}

// --- Su 命令实现 ---
type cmdSu struct{}

func (cmdSu) execute(context commandContext) (uint32, error) {
	// Simplified su: Starts a new shell instance with a different user
	newContextUser := "root" // Default to root
	if len(context.args) > 1 {
		newContextUser = context.args[1] // Switch to specified user (no password check)
	}
	// Create context for the sub-shell
	subShellContext := commandContext{
		args:     shellProgram, // Command to execute is "sh"
		stdin:    context.stdin,
		stdout:   context.stdout,
		stderr:   context.stderr,
		pty:      context.pty,
		user:     newContextUser, // Use the new user
		// cwd and hostname will be re-initialized by the new cmdShell instance
	}
	// Execute the new shell
	shellCmd := cmdShell{}
	return shellCmd.execute(subShellContext)
}

// --- Uname 命令实现 ---
type cmdUname struct{}


func (cmdUname) execute(context commandContext) (uint32, error) {
	// Simulate uname -a
	kernelRelease := "5.15.0-101-generic" // Keep kernel version consistent
	kernelVersion := fmt.Sprintf("#1-Linux SMP Tue Mar 26 15:04:31 UTC 2024") // Specific build info
	machine := "x86_64"
	processor := "x86_64" // Often same as machine or unknown
	hwPlatform := "x86_64" // Often same as machine
	osName := "Linux"

	fakeUnameAll := fmt.Sprintf("Linux %s %s %s %s %s %s %s",
		context.hostname, kernelRelease, kernelVersion, machine, processor, hwPlatform, osName)

	output := fakeUnameAll // Default output is 'uname -a'

	if len(context.args) > 1 {
		switch context.args[1] {
		case "-s", "--kernel-name":
			output = "Linux" // Still Linux underneath
		case "-n", "--nodename":
			output = context.hostname
		case "-r", "--kernel-release":
			output = kernelRelease
		case "-v", "--kernel-version":
			output = kernelVersion
		case "-m", "--machine":
			output = machine
		case "-p", "--processor":
			output = processor
		case "-i", "--hardware-platform":
			output = hwPlatform
		case "-o", "--operating-system":
			output = osName
		case "-a", "--all":
			output = fakeUnameAll
		default:
			// Unknown flag, print error or default to -a
			output = fakeUnameAll
		}
	}

	_, err := fmt.Fprintln(context.stdout, output)
	if err != nil {
		return 1, err
	}
	return 0, nil
}

// --- Pwd 命令实现 ---
type cmdPwd struct{}

func (cmdPwd) execute(context commandContext) (uint32, error) {
	// Print the current working directory from context
	if context.cwd == nil {
		// Should not happen if called from within the shell
		_, err := fmt.Fprintln(context.stderr, "pwd: 无法获取当前工作目录")
		return 1, err
	}
	_, err := fmt.Fprintln(context.stdout, *context.cwd)
	if err != nil {
		return 1, err
	}
	return 0, nil
}

// --- Id 命令实现 ---
type cmdId struct{}

func (cmdId) execute(context commandContext) (uint32, error) {
	// Simulate user/group IDs
	var uid, gid uint32
	var group string
	switch context.user {
	case "root":
		uid, gid, group = 0, 0, "root"
	default:
		uid, gid, group = 1000, 1000, context.user // Assign default IDs
	}
	output := fmt.Sprintf("uid=%d(%s) gid=%d(%s) groups=%d(%s)", uid, context.user, gid, group, gid, group) // Simplified groups
	_, err := fmt.Fprintln(context.stdout, output)
	if err != nil {
		return 1, err
	}
	return 0, nil
}

// --- Hostname 命令实现 ---
type cmdHostname struct{}

func (cmdHostname) execute(context commandContext) (uint32, error) {
	// Print the hostname from context
	_, err := fmt.Fprintln(context.stdout, context.hostname)
	if err != nil {
		return 1, err
	}
	return 0, nil
}

// --- Cd 命令实现 ---
type cmdCd struct{}

const baseDir = "/home/guest" // Base directory restriction

func (cmdCd) execute(context commandContext) (uint32, error) {
	if context.cwd == nil {
		_, err := fmt.Fprintln(context.stderr, "cd: 无法获取当前工作目录")
		return 1, err
	}

	// Determine target directory (default to baseDir if no argument)
	targetDir := baseDir
	if len(context.args) > 1 {
		targetDir = context.args[1]
	}

	currentDir := *context.cwd
	var newDir string

	// Calculate the new absolute path
	if filepath.IsAbs(targetDir) {
		newDir = filepath.Clean(targetDir)
	} else {
		newDir = filepath.Clean(filepath.Join(currentDir, targetDir))
	}

	// --- Cd 限制逻辑 ---
	// Prevent changing to '/' or any directory above baseDir
	if (!strings.HasPrefix(newDir, baseDir) && newDir != baseDir) || newDir == "/" {
		_, err := fmt.Fprintf(context.stderr, "%s: cd: %s: 权限不足或目录不存在\n", context.hostname, targetDir)
		return 1, err // Return 1 for permission denied/not found
	}

	// --- 更新工作目录 ---
	// In this virtual environment, we don't check if the directory actually exists
	*context.cwd = newDir // Update the shell's current working directory state

	return 0, nil // Success
}

// --- Wpm 命令实现 (Fake Package Manager) ---
type cmdWpm struct{}

const wpmUpstream = "https://mirrors.tuna.tsinghua.edu.cn/debian" // Define the fake upstream URL

func (cmdWpm) execute(context commandContext) (uint32, error) {
	if len(context.args) < 2 {
		// Show usage if only 'wpm' is entered
		_, err := fmt.Fprintf(context.stderr, "用法: wpm <指令> [选项...]\n支持的指令: update, list, search, install, remove\n")
		return 1, err
	}

	subCommand := context.args[1]
	var err error // Declare err for reuse

	switch subCommand {
	case "update", "upgrade":
		// Simulate update failure
		_, _ = fmt.Fprintf(context.stdout, "正在获取软件包列表 %s ...\n", wpmUpstream)
		time.Sleep(1 * time.Second) // Simulate network delay
		// Print fake kernel error
		// (Error message slightly updated to reference the new domain)
		_, err = fmt.Fprintf(context.stderr, `
kernel: general protection fault: 0000 [#1] SMP PTI
CPU: 0 PID: 1234 Comm: wpm Tainted: G        W        5.15.0-101-generic #1-WindOS
Hardware name: QEMU QEMU Virtual Machine, BIOS 0.0.0 02/06/2015
RIP: 0010:0x0
Code: Bad RIP value.
RSP: 0018:ffffc90000abcde0 EFLAGS: 00010246
RAX: 0000000000000000 RBX: 0000000000000001 RCX: 0000000000000000
RDX: 0000000000000000 RSI: 0000000000000000 RDI: 0000000000000000
RBP: ffffc90000abcdf0 R08: 0000000000000000 R09: 0000000000000000
R10: 0000000000000000 R11: 0000000000000000 R12: 0000000000000000
R13: 0000000000000000 R14: 0000000000000000 R15: 0000000000000000
FS:  00007f0000000000(0000) GS:ffff888888888888(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 0000000000000000 CR3: 000000011abcdef0 CR4: 00000000000406f0
Call Trace:
 ? panic+0x1a/0x20
 ? oops_end+0xb0/0xb0
 ? die+0x43/0x50
 ? do_general_protection+0x74/0x80
 ? general_protection_interrupt+0x2e/0x30
 <IRQ>
 ? net_rx_action+0x14e/0x3a0
 ? __do_softirq+0xe1/0x2c2
 ? irq_exit_rcu+0x95/0xc0
 ? sysvec_apic_timer_interrupt+0x4d/0x90
 </IRQ>
 ? asm_sysvec_apic_timer_interrupt+0x12/0x20
RIP: 0010:0x0
---[ end trace ]---
错误：内核在尝试连接 %s 时发生中断错误。无法更新软件包列表。
`, wpmUpstream)
		return 1, err // Return error status code

	case "list", "search":
		_, err = fmt.Fprintln(context.stderr, "错误：需要先运行 'wpm update' 更新软件包列表。")
		return 1, err

	case "install":
		if len(context.args) < 3 {
			_, err = fmt.Fprintf(context.stderr, "用法: wpm install <软件包名称>\n")
			return 1, err
		}
		_, err = fmt.Fprintf(context.stderr, "错误：需要先运行 'wpm update' 更新软件包列表才能安装 '%s'。\n", context.args[2])
		return 1, err

	case "remove", "purge":
		if len(context.args) < 3 {
			_, err = fmt.Fprintf(context.stderr, "用法: wpm remove <软件包名称>\n")
			return 1, err
		}
		_, err = fmt.Fprintf(context.stderr, "错误：软件包 '%s' 是系统核心组件或受保护，此环境不允许移除。\n", context.args[2])
		return 1, err

	default:
		_, err = fmt.Fprintf(context.stderr, "%s: wpm: 未知的指令 '%s'\n", context.hostname, subCommand)
		return 1, err
	}
}

// --- Apt / Apt-Get 命令实现 (提示用户使用 wpm) ---
type cmdApt struct{}

func (cmdApt) execute(context commandContext) (uint32, error) {
	// Print message suggesting 'wpm' instead
	_, err := fmt.Fprintln(context.stderr, "提示：请使用 'wpm' 指令进行包管理")
	return 1, err // Return error code 1 indicating command didn't succeed
}

type cmdAptGet struct{}

func (cmdAptGet) execute(context commandContext) (uint32, error) {
	// Use the same logic as 'apt'
	aptCmd := cmdApt{}
	return aptCmd.execute(context)
}

// --- Lscpu 命令实现 ---
type cmdLscpu struct{}

func (cmdLscpu) execute(context commandContext) (uint32, error) {
	// Simulate output for AMD Athlon X4 645, cause it's my workstation's CPU :)
	output := `Architecture:        x86_64
CPU op-mode(s):      32-bit, 64-bit
Byte Order:          Little Endian
CPU(s):              4
On-line CPU(s) list: 0-3
Thread(s) per core:  1
Core(s) per socket:  4
Socket(s):           1
NUMA node(s):        1
Vendor ID:           AuthenticAMD
CPU family:          16
Model:               5
Model name:          AMD Athlon(tm) II X4 645 Processor
Stepping:            3
CPU MHz:             3100.000
CPU max MHz:         3100.0000
CPU min MHz:         800.0000
BogoMIPS:            6200.00
Virtualization:      AMD-V
L1d cache:           64K
L1i cache:           64K
L2 cache:            512K
NUMA node0 CPU(s):   0-3
Flags:               fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx mmxext fxsr_opt pdpe1gb rdtscp lm 3dnowext 3dnow constant_tsc rep_good nopl nonstop_tsc cpuid extd_apicid amd_dcm aperfmperf pni monitor cx16 popcnt lahf_lm cmp_legacy svm extapic cr8_legacy abm sse4a misalignsse 3dnowprefetch osvw ibs skinit wdt nodeid_msr npt lbrv svm_lock nrip_save
`
	_, err := fmt.Fprint(context.stdout, output) // Use Fprint for multi-line string without extra newline
	if err != nil {
		return 1, err
	}
	return 0, nil
}

// --- Free 命令实现 ---
// There may have problems
type cmdFree struct{}

func (cmdFree) execute(context commandContext) (uint32, error) {
	// Simulate 'free' output for ~0.5GB RAM (512MiB) in KiB
	// Total: 512 * 1024 = 524288 KiB
	totalMem := 524288
	// Simulate some usage (randomized slightly for variation)
	usedMem := 150000 + rand.Intn(50000) // ~150-200 MiB used
	sharedMem := 5000 + rand.Intn(2000)   // ~5-7 MiB shared
	buffCache := 100000 + rand.Intn(30000) // ~100-130 MiB buff/cache
	freeMem := totalMem - usedMem - buffCache // Calculate free based on others
	if freeMem < 0 { freeMem = 0 } // Ensure non-negative
	// Available is roughly free + reclaimable cache/buffers (simplified)
	availableMem := freeMem + (buffCache / 3) // Crude approximation
	if availableMem > totalMem - usedMem + sharedMem { // Cap available
		availableMem = totalMem - usedMem + sharedMem
	}


	// Simulate small swap
	totalSwap := 131072 // 128 MiB swap
	usedSwap := 1000 + rand.Intn(5000)
	freeSwap := totalSwap - usedSwap

	// Format the output similar to 'free' command (values in KiB)
	// Right-align numbers using fmt.Sprintf padding
	output := fmt.Sprintf("%10s %10s %10s %10s %10s %10s\n", "", "total", "used", "free", "shared", "buff/cache", "available")
	output += fmt.Sprintf("%-10s %10d %10d %10d %10d %10d %10d\n", "Mem:", totalMem, usedMem, freeMem, sharedMem, buffCache, availableMem)
	output += fmt.Sprintf("%-10s %10d %10d %10d\n", "Swap:", totalSwap, usedSwap, freeSwap)

	_, err := fmt.Fprint(context.stdout, output)
	if err != nil {
		return 1, err
	}
	return 0, nil
}

// --- Lspci 命令实现 ---
type cmdLspci struct{}

func (cmdLspci) execute(context commandContext) (uint32, error) {
	// Report an error as PCI access is not available/allowed
	_, err := fmt.Fprintln(context.stderr, "lspci: 此环境下无法读取 PCI 设备列表。")
	// Alternatively, mimic a system error:
	// _, err := fmt.Fprintln(context.stderr, "lspci: Cannot open /sys/bus/pci/devices: No such file or directory")
	return 1, err // Return 1 to indicate failure
}


// main function (example for standalone execution)
// func main() {
//  // ... (setup code as before, but useless(maybe), so I deleted it) ...
// }
