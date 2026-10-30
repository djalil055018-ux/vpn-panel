package main

import "vpn-platform/internal/model"

type runtimeRecoveryInfoProvider interface {
	RuntimeRecoveryInfo() model.RuntimeRecoveryInfo
}

func runtimeRecoveryInfo(
	driver any,
) model.RuntimeRecoveryInfo {
	provider, ok := driver.(runtimeRecoveryInfoProvider)
	if !ok {
		return model.RuntimeRecoveryInfo{}
	}

	return provider.RuntimeRecoveryInfo()
}
