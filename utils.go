package main

import "fmt"

func HelperFuncSupportPrint(support bool, helper_func_name string) {

	if support {
		fmt.Printf("%s support\n", helper_func_name)
	} else {
		fmt.Printf("%s not support\n", helper_func_name)
	}
}

func AttachTypeSupportPrint(support bool, attach_type_name string) {

	if support {
		fmt.Printf("%s support\n", attach_type_name)
	} else {
		fmt.Printf("%s not support\n", attach_type_name)
	}
}

func OtherSupportPrint(support bool, other_support_name string) {

	if support {
		fmt.Printf("%s support\n", other_support_name)
	} else {
		fmt.Printf("%s not support\n", other_support_name)
	}
}
