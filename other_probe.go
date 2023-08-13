package main

import (
	"fmt"

	"github.com/cilium/cilium/pkg/datapath/linux/probes"
	"github.com/cilium/cilium/pkg/sysctl"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

func OtherProbe() {
	var other_feature string

	fmt.Println("=================== Other System Feature =================")
	other_feature = "XDP/bpf_jiffies64"
	if probes.HaveProgramHelper(ebpf.XDP, asm.FnJiffies64) == nil {
		HelperFuncSupportPrint(true, other_feature)
		other_feature = "Jiffies"
		t, err := probes.Jiffies()
		if err == nil && t > 0 {
			OtherSupportPrint(true, other_feature)
		} else {
			OtherSupportPrint(false, other_feature)
			fmt.Println("kernel doesn't expose jiffies")
		}
	} else {
		HelperFuncSupportPrint(false, other_feature)
		fmt.Println("kernel support is missing (Linux 5.5 or later required).")
	}

	other_feature = "net.core.default_qdisc"
	if _, err := sysctl.Read("net.core.default_qdisc"); err != nil {
		OtherSupportPrint(false, other_feature)
		fmt.Println("BPF bandwidth manager could not read procfs. Disabling the feature.")
	} else {
		OtherSupportPrint(true, other_feature)
	}

	other_feature = "HaveLargeInstructionLimit"
	if probes.HaveLargeInstructionLimit() != nil {
		OtherSupportPrint(false, other_feature)
		fmt.Println("The kernel does not support the 1 Million instruction limit.")
	} else {
		OtherSupportPrint(true, other_feature)
	}
}
