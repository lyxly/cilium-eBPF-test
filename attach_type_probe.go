package main

import (
	"fmt"

	"github.com/cilium/cilium/pkg/datapath/linux/probes"
	"github.com/cilium/ebpf"
)

func attach_type_probe() {
	var ebpf_attach_type string

	fmt.Println("=================== Attach Type =================")
	ebpf_attach_type = "CGROUP_SOCK_ADDR, BPF_CGROUP_INET4_GETPEERNAME"
	if err := probes.HaveAttachType(ebpf.CGroupSockAddr, ebpf.AttachCgroupInet4GetPeername); err != nil {
		AttachTypeSupportPrint(false, ebpf_attach_type)
		fmt.Println("option.Config.EnableSocketLBPeer = false")
	} else {
		AttachTypeSupportPrint(true, ebpf_attach_type)
	}

	ebpf_attach_type = "CGROUP_SOCK_ADDR, BPF_CGROUP_INET4_CONNECT"
	if err := probes.HaveAttachType(ebpf.CGroupSockAddr, ebpf.AttachCGroupInet4Connect); err != nil {
		AttachTypeSupportPrint(false, ebpf_attach_type)
		fmt.Printf("BPF host-reachable services for TCP needs kernel 4.17.0 or newer: %s\n", err)
	} else {
		AttachTypeSupportPrint(true, ebpf_attach_type)
	}

	ebpf_attach_type = "CGROUP_SOCK_ADDR, BPF_CGROUP_UDP4_RECVMSG"
	if err := probes.HaveAttachType(ebpf.CGroupSockAddr, ebpf.AttachCGroupUDP4Recvmsg); err != nil {
		AttachTypeSupportPrint(false, ebpf_attach_type)
		fmt.Printf("BPF host-reachable services for UDP needs kernel 4.19.57, 5.1.16, 5.2.0 or newer: %s\n", err)
	} else {
		AttachTypeSupportPrint(true, ebpf_attach_type)
	}

	ebpf_attach_type = "CGROUP_SOCK_ADDR, BPF_CGROUP_INET6_GETPEERNAME"
	if err := probes.HaveAttachType(ebpf.CGroupSockAddr, ebpf.AttachCgroupInet6GetPeername); err != nil {
		AttachTypeSupportPrint(false, ebpf_attach_type)
		fmt.Println("option.Config.EnableSocketLBPeer = false")
	} else {
		AttachTypeSupportPrint(true, ebpf_attach_type)
	}

	ebpf_attach_type = "CGROUP_SOCK_ADDR, BPF_CGROUP_INET6_CONNECT"
	if err := probes.HaveAttachType(ebpf.CGroupSockAddr, ebpf.AttachCGroupInet6Connect); err != nil {
		AttachTypeSupportPrint(false, ebpf_attach_type)
		fmt.Printf("BPF host-reachable services for TCP needs kernel 4.17.0 or newer: %s", err)
	} else {
		AttachTypeSupportPrint(true, ebpf_attach_type)
	}

	ebpf_attach_type = "CGROUP_SOCK_ADDR, BPF_CGROUP_UDP6_RECVMSG"
	if err := probes.HaveAttachType(ebpf.CGroupSockAddr, ebpf.AttachCGroupUDP6Recvmsg); err != nil {
		AttachTypeSupportPrint(false, ebpf_attach_type)
		fmt.Printf("BPF host-reachable services for UDP needs kernel 4.19.57, 5.1.16, 5.2.0 or newer: %s", err)
	} else {
		AttachTypeSupportPrint(true, ebpf_attach_type)
	}
}
