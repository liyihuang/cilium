// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

type allIngressDenyFromOutside struct{}

func (t allIngressDenyFromOutside) build(ct *check.ConnectivityTest, _ map[string]string) {
	newTest("all-ingress-deny-from-outside", ct).
		WithCondition(func() bool { return ct.Params().IncludeUnsafeTests }).
		WithCiliumPolicy(denyAllIngressPolicyYAML).
		WithFeatureRequirements(features.RequireEnabled(features.NodeWithoutCilium)).
		WithIPRoutesFromOutsideToPodCIDRs().
		WithScenarios(tests.FromCIDRToPod()).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().Address(features.GetIPFamily(ct.Params().ExternalOtherIPv4)) == ct.Params().ExternalOtherIPv4 ||
				a.Destination().Address(features.GetIPFamily(ct.Params().ExternalIPv4)) == ct.Params().ExternalIPv4 {
				return check.ResultOK, check.ResultNone
			}
			return check.ResultDrop, check.ResultDefaultDenyIngressDrop
		})
}
