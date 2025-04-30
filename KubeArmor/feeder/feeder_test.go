// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package feeder

import (
	"flag"
	"sync"
	"testing"

	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
	pb "github.com/kubearmor/KubeArmor/protobuf"
)

func TestFeeder(t *testing.T) {
	// node
	node := tp.Node{}
	nodeLock := new(sync.RWMutex)

	// load configuration
	flag.CommandLine = flag.NewFlagSet("TestFeeder", flag.ContinueOnError)
	if err := cfg.LoadConfig(); err != nil {
		t.Log("[FAIL] Failed to load configuration")
		return
	}

	// create logger
	logger := NewFeeder(&node, &nodeLock)
	if logger == nil {
		t.Log("[FAIL] Failed to create logger")
		return
	}
	t.Log("[PASS] Created logger")

	// destroy logger
	if err := logger.DestroyFeeder(); err != nil {
		t.Log("[FAIL] Failed to destroy logger")
		return
	}
	t.Log("[PASS] Destroyed logger")
}

func TestMarshalVisibilityLog(t *testing.T) {
	flag.CommandLine = flag.NewFlagSet("TestMarhsalVisibilityLog", flag.ContinueOnError)
	if err := cfg.LoadConfig(); err != nil {
		t.Log("[FAIL] Failed to load configuration")
		return
	}
	// example visibility log
	visibilityLog := tp.Log{
		ClusterName: "default",
		// exclude hostname for unittest since it is set using node info from feeder
		// HostName:          "kubearmor-dev2",
		Type:              "HostLog",
		Source:            "/usr/bin/dockerd",
		Resource:          "/usr/bin/runc --version",
		Operation:         "Process",
		Data:              "syscall=SYS_EXECVE",
		Result:            "Passed",
		HostPID:           193088,
		HostPPID:          914,
		PID:               193088,
		PPID:              914,
		ParentProcessName: "/usr/bin/dockerd",
		ProcessName:       "/usr/bin/runc",
	}

	expectedMarshaledLog := &pb.Log{
		ClusterName: "default",
		// HostName:          "kubearmor-dev2",
		Type:              "HostLog",
		Source:            "/usr/bin/dockerd",
		Resource:          "/usr/bin/runc --version",
		Operation:         "Process",
		Data:              "syscall=SYS_EXECVE",
		Result:            "Passed",
		HostPID:           193088,
		HostPPID:          914,
		PID:               193088,
		PPID:              914,
		ParentProcessName: "/usr/bin/dockerd",
		ProcessName:       "/usr/bin/runc",
	}

	// marshal visibility log and check result
	marshaledLog := MarshalVisibilityLog(visibilityLog)
	if marshaledLog != expectedMarshaledLog {
		t.Logf("[FAIL] Expected marshaled log: %+v", expectedMarshaledLog)
		t.Logf("but got: %+v", marshaledLog)
	}

	// do the same but with dropped resource field
	cfg.GlobalCfg.DropResourceFromProcessLogs = true
	expectedMarshaledLog.Resource = ""
	marshaledLog = MarshalVisibilityLog(visibilityLog)
	if marshaledLog != expectedMarshaledLog {
		t.Logf("[FAIL] Expected marshaled log: %+v", expectedMarshaledLog)
		t.Logf("but got: %+v", marshaledLog)
	}
}
