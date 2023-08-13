package main

import (
	"fmt"

	"github.com/cilium/cilium/pkg/datapath/linux/probes"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

func helper_func_probe() {
	var ebpf_helper_func string

	fmt.Println("================== Helper Function ================")
	ebpf_helper_func = "SCHED_CLS/bpf_sk_assign"
	if probes.HaveProgramHelper(ebpf.SchedCLS, asm.FnSkAssign) != nil {
		HelperFuncSupportPrint(false, ebpf_helper_func)
		fmt.Println("Disabled support for BPF TProxy due to missing kernel support for socket assign (Linux 5.7 or later)")
	} else {
		HelperFuncSupportPrint(true, ebpf_helper_func)
	}

	ebpf_helper_func = "SCHED_CLS/bpf_redirect_neigh"
	if probes.HaveProgramHelper(ebpf.SchedCLS, asm.FnRedirectNeigh) != nil {
		HelperFuncSupportPrint(false, ebpf_helper_func)
		fmt.Println("BPF host routing requires kernel 5.10 or newer.")
	} else {
		HelperFuncSupportPrint(true, ebpf_helper_func)
	}

	ebpf_helper_func = "SCHED_CLS/bpf_redirect_peer"
	if probes.HaveProgramHelper(ebpf.SchedCLS, asm.FnRedirectPeer) != nil {
		HelperFuncSupportPrint(false, ebpf_helper_func)
		fmt.Println("BPF host routing requires kernel 5.10 or newer.")
	} else {
		HelperFuncSupportPrint(true, ebpf_helper_func)
	}

	ebpf_helper_func = "SCHED_CLS/bpf_fib_lookup"
	if probes.HaveProgramHelper(ebpf.SchedCLS, asm.FnFibLookup) != nil {
		HelperFuncSupportPrint(false, ebpf_helper_func)
		fmt.Println("BPF NodePort services needs kernel 4.17.0 or newer")
	} else {
		HelperFuncSupportPrint(true, ebpf_helper_func)
	}

	ebpf_helper_func = "XDP/bpf_ktime_get_boot_ns"
	if probes.HaveProgramHelper(ebpf.XDP, asm.FnKtimeGetBootNs) != nil {
		HelperFuncSupportPrint(false, ebpf_helper_func)
		fmt.Printf("pcap recorder --%s datapath needs kernel 5.8.0 or newer\n", "enable-recorder")
	} else {
		HelperFuncSupportPrint(true, ebpf_helper_func)
	}

	ebpf_helper_func = "CGROUP_SOCK_ADDR/bpf_getsockopt"
	if probes.HaveProgramHelper(ebpf.CGroupSockAddr, asm.FnGetsockopt) != nil {
		HelperFuncSupportPrint(false, ebpf_helper_func)
		fmt.Println("BPF load-balancer health check datapath needs kernel 5.12.0 or newer. Disabling BPF load-balancer health check datapath.")
	} else {
		HelperFuncSupportPrint(true, ebpf_helper_func)
	}

	ebpf_helper_func = "CGROUP_SOCK_ADDR/bpf_get_cgroup_classid"
	if probes.HaveProgramHelper(ebpf.CGroupSockAddr, asm.FnGetCgroupClassid) != nil {
		HelperFuncSupportPrint(false, ebpf_helper_func)
		fmt.Printf("BPF kube-proxy replacement under MKE with --%s needs kernel 5.7 or newer\n", "enable-mke")
	} else {
		HelperFuncSupportPrint(true, ebpf_helper_func)
	}

	ebpf_helper_func = "CGROUP_SOCK_ADDR/bpf_get_netns_cookie"
	if probes.HaveProgramHelper(ebpf.CGroupSockAddr, asm.FnGetNetnsCookie) != nil {
		HelperFuncSupportPrint(false, ebpf_helper_func)
		fmt.Printf("BPF kube-proxy replacement under MKE with --%s needs kernel 5.7 or newer\n", "enable-mke")
	} else {
		HelperFuncSupportPrint(true, ebpf_helper_func)
	}

	ebpf_helper_func = "CGROUP_SOCK_ADDR/bpf_perf_event_output"
	if probes.HaveProgramHelper(ebpf.CGroupSockAddr, asm.FnPerfEventOutput) != nil {
		HelperFuncSupportPrint(false, ebpf_helper_func)
		fmt.Println("Disabling socket-LB tracing as it requires kernel 5.7 or newer")
	} else {
		HelperFuncSupportPrint(true, ebpf_helper_func)
	}

	ebpf_helper_func = "CGROUP_SOCK_ADDR/bpf_get_netns_cookie"
	if probes.HaveProgramHelper(ebpf.CGroupSockAddr, asm.FnGetNetnsCookie) != nil {
		HelperFuncSupportPrint(false, ebpf_helper_func)
		fmt.Println("Session affinity for host reachable services needs kernel 5.7.0 or newer " +
			"to work properly when accessed from inside cluster: the same service endpoint " +
			"will be selected from all network namespaces on the host.")
	} else {
		HelperFuncSupportPrint(true, ebpf_helper_func)
	}

	ebpf_helper_func = "CGROUP_SOCK/bpf_get_netns_cookie"
	if probes.HaveProgramHelper(ebpf.CGroupSock, asm.FnGetNetnsCookie) != nil {
		HelperFuncSupportPrint(false, ebpf_helper_func)
		fmt.Println("Session affinity for host reachable services needs kernel 5.7.0 or newer " +
			"to work properly when accessed from inside cluster: the same service endpoint " +
			"will be selected from all network namespaces on the host.")
	} else {
		HelperFuncSupportPrint(true, ebpf_helper_func)
	}

	ebpf_helper_func = "CGROUP_SOCK_ADDR/bpf_get_netns_cookie"
	if probes.HaveProgramHelper(ebpf.CGroupSockAddr, asm.FnGetNetnsCookie) != nil {
		HelperFuncSupportPrint(false, ebpf_helper_func)
		fmt.Println("Without network namespace cookie lookup functionality, BPF datapath " +
			"cannot distinguish root and non-root namespace, skipping socket-level " +
			"loadbalancing will not work. Istio routing chains will be missed. " +
			"Needs kernel version >= 5.7")
	} else {
		HelperFuncSupportPrint(true, ebpf_helper_func)
	}

	// We at least need 5.1 kernel for native TCP EDT integration
	// and writable queue_mapping that we use. Below helper is
	// available for 5.1 kernels and onwards.
	ebpf_helper_func = "SCHED_CLS/bpf_skb_ecn_set_ce"
	if probes.HaveProgramHelper(ebpf.SchedCLS, asm.FnSkbEcnSetCe) != nil {
		HelperFuncSupportPrint(false, ebpf_helper_func)
		fmt.Println("BPF bandwidth manager needs kernel 5.1 or newer. Disabling the feature.")
	} else {
		HelperFuncSupportPrint(true, ebpf_helper_func)
	}

	ebpf_helper_func = "SCHED_CLS/bpf_skb_set_tstamp"
	if probes.HaveProgramHelper(ebpf.SchedCLS, asm.FnSkbSetTstamp) != nil {
		HelperFuncSupportPrint(false, ebpf_helper_func)
		fmt.Printf("Cannot enable --%s, needs kernel 5.18 or newer.\n", "enable-bbr")
	} else {
		HelperFuncSupportPrint(true, ebpf_helper_func)
	}

	ebpf_helper_func = "SCHED_CLS/bpf_skb_change_head"
	// supportL3Dev returns true if the kernel is new enough to support BPF host routing of
	// packets coming from L3 devices using bpf_skb_redirect_peer.
	//func supportL3Dev() bool {
	if probes.HaveProgramHelper(ebpf.SchedCLS, asm.FnSkbChangeHead) != nil {
		HelperFuncSupportPrint(false, ebpf_helper_func)
	} else {
		HelperFuncSupportPrint(true, ebpf_helper_func)
	}
	// }
	ebpf_helper_func = "CGROUP_SOCK_ADDR/bpf_sk_lookup_tcp"
	if probes.HaveProgramHelper(ebpf.CGroupSockAddr, asm.FnSkLookupTcp) != nil {
		HelperFuncSupportPrint(false, ebpf_helper_func)
		fmt.Println("Without socket lookup kernel functionality, BPF " +
			"datapath cannot prevent potential loop caused by local-redirect" +
			"service translation. Needs kernel version >= 5.1")
	} else {
		HelperFuncSupportPrint(true, ebpf_helper_func)
	}

	ebpf_helper_func = "CGROUP_SOCK_ADDR/bpf_sk_lookup_udp"
	if probes.HaveProgramHelper(ebpf.CGroupSockAddr, asm.FnSkLookupUdp) != nil {
		HelperFuncSupportPrint(false, ebpf_helper_func)
		fmt.Println("Without socket lookup kernel functionality, BPF " +
			"datapath cannot prevent potential loop caused by local-redirect" +
			"service translation. Needs kernel version >= 5.1")
	} else {
		HelperFuncSupportPrint(true, ebpf_helper_func)
	}
}
