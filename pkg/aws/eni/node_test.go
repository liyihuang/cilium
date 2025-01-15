// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package eni

import (
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/aws/eni/types"
	eniTypes "github.com/cilium/cilium/pkg/aws/eni/types"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

var (
	testSubnets = ipamTypes.SubnetMap{
		"subnet-1": {
			ID:                 "subnet-1",
			AvailabilityZone:   "us-west-1",
			VirtualNetworkID:   "vpc-1",
			AvailableAddresses: 10,
		},
		"subnet-2": {
			ID:                 "subnet-2",
			AvailabilityZone:   "us-west-1",
			VirtualNetworkID:   "vpc-1",
			AvailableAddresses: 10,
		},
	}
	testRouteTableSlice = []*ipamTypes.RouteTable{
		{
			ID:               "rt-1",
			VirtualNetworkID: "vpc-1",
			Subnets: map[string]struct{}{
				"subnet-1": {},
				"subnet-2": {},
			},
		},
	}
)

func sliceToMap(tables []*ipamTypes.RouteTable) ipamTypes.RouteTableMap {
	m := ipamTypes.RouteTableMap{}
	for _, t := range tables {
		m[t.ID] = t
	}
	return m
}

func newCiliumNode(name string, opts ...func(*v2.CiliumNode)) *v2.CiliumNode {
	cn := &v2.CiliumNode{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec: v2.NodeSpec{
			IPAM: ipamTypes.IPAMSpec{
				Pool: ipamTypes.AllocationMap{},
			},
		},
		Status: v2.NodeStatus{
			IPAM: ipamTypes.IPAMStatus{
				Used: ipamTypes.AllocationMap{},
			},
		},
	}

	for _, opt := range opts {
		opt(cn)
	}

	return cn
}

func withInstanceType(instanceType string) func(*v2.CiliumNode) {
	return func(cn *v2.CiliumNode) {
		cn.Spec.ENI.InstanceType = instanceType
	}
}

func withFirstInterfaceIndex(index int) func(*v2.CiliumNode) {
	return func(cn *v2.CiliumNode) {
		cn.Spec.ENI.FirstInterfaceIndex = &index
	}
}

func TestGetMaximumAllocatableIPv4(t *testing.T) {
	n := &Node{}

	// With no k8sObj defined, it should return 0
	require.Equal(t, 0, n.GetMaximumAllocatableIPv4())

	// With instance-type = m5.large and first-interface-index = 0, we should be able to allocate up to 3x10-3 addresses
	n.k8sObj = newCiliumNode("node", withInstanceType("m5.large"), withFirstInterfaceIndex(0))
	require.Equal(t, 27, n.GetMaximumAllocatableIPv4())

	// With instance-type = m5.large and first-interface-index = 1, we should be able to allocate up to 2x10-2 addresses
	n.k8sObj = newCiliumNode("node", withInstanceType("m5.large"), withFirstInterfaceIndex(1))
	require.Equal(t, 18, n.GetMaximumAllocatableIPv4())

	// With instance-type = m5.large and first-interface-index = 4, we should return 0 as there is only 3 interfaces
	n.k8sObj = newCiliumNode("node", withInstanceType("m5.large"), withFirstInterfaceIndex(4))
	require.Equal(t, 0, n.GetMaximumAllocatableIPv4())

	// With instance-type = foo we should return 0
	n.k8sObj = newCiliumNode("node", withInstanceType("foo"))
	require.Equal(t, 0, n.GetMaximumAllocatableIPv4())
}

// TestGetUsedIPWithPrefixes tests the logic computing used IPs on a node when prefix delegation is enabled.
func TestGetUsedIPWithPrefixes(t *testing.T) {
	cn := newCiliumNode("node1", withInstanceType("m5a.large"))
	n := &Node{k8sObj: cn}
	eniName := "eni-1"
	prefixes := []string{"10.10.128.0/28", "10.10.128.16/28"}
	eniMap := make(map[string]types.ENI)
	eniMap[eniName] = types.ENI{Prefixes: prefixes}
	cn.Status.ENI.ENIs = eniMap

	allocationMap := make(ipamTypes.AllocationMap)
	allocationMap["10.10.128.2"] = ipamTypes.AllocationIP{Resource: eniName}
	allocationMap["10.10.128.18"] = ipamTypes.AllocationIP{Resource: eniName}
	n.k8sObj.Status.IPAM.Used = allocationMap
	require.Equal(t, 32, n.GetUsedIPWithPrefixes())
}

func TestFindSubnetInSameRouteTableWithNodeSubnet(t *testing.T) {
	setup(t)

	tests := []struct {
		name           string
		nodeSubnetID   string
		subnetIDs      []string
		expectedSubnet string
	}{
		{
			name:           "find subnet with most addresses in same route table",
			nodeSubnetID:   "subnet-1",
			subnetIDs:      []string{"subnet-1", "subnet-2"},
			expectedSubnet: "subnet-2",
		},
		{
			name:           "no suitable subnet found in different route table",
			nodeSubnetID:   "subnet-1",
			subnetIDs:      []string{"subnet-1", "subnet-3"},
			expectedSubnet: "",
		},
		{
			name:           "skip node subnet when finding best subnet",
			nodeSubnetID:   "subnet-2",
			subnetIDs:      []string{"subnet-1", "subnet-2"},
			expectedSubnet: "subnet-1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := &Node{
				manager: &InstancesManager{
					subnets:     testSubnets,
					routeTables: sliceToMap(testRouteTableSlice),
				},
				k8sObj: &v2.CiliumNode{
					Spec: v2.NodeSpec{
						ENI: eniTypes.ENISpec{
							NodeSubnetID: tt.nodeSubnetID,
							SubnetIDs:    tt.subnetIDs,
						},
					},
				},
			}

			bestSubnet := n.FindSubnetInSameRouteTableWithNodeSubnet()

			if tt.expectedSubnet == "" {
				require.Nil(t, bestSubnet)
			} else {
				require.NotNil(t, bestSubnet)
				require.Equal(t, tt.expectedSubnet, bestSubnet.ID)
			}
		})
	}
}

func TestCheckSubnetInSameRouteTableWithNodeSubnet(t *testing.T) {
	setup(t)

	tests := []struct {
		name         string
		nodeSubnetID string
		testSubnetID string
		expected     bool
	}{
		{
			name:         "same route table",
			nodeSubnetID: "subnet-1",
			testSubnetID: "subnet-2",
			expected:     true,
		},
		{
			name:         "different route tables",
			nodeSubnetID: "subnet-1",
			testSubnetID: "subnet-3",
			expected:     false,
		},
		{
			name:         "subnet not found",
			nodeSubnetID: "subnet-1",
			testSubnetID: "subnet-nonexistent",
			expected:     false,
		},
		{
			name:         "node subnet not found",
			nodeSubnetID: "subnet-nonexistent",
			testSubnetID: "subnet-1",
			expected:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := &Node{
				manager: &InstancesManager{
					routeTables: sliceToMap(testRouteTableSlice),
				},
				k8sObj: &v2.CiliumNode{
					Spec: v2.NodeSpec{
						ENI: eniTypes.ENISpec{
							NodeSubnetID: tt.nodeSubnetID,
						},
					},
				},
			}

			testSubnet := &ipamTypes.Subnet{
				ID: tt.testSubnetID,
			}

			result := n.CheckSubnetInSameRouteTableWithNodeSubnet(testSubnet)
			require.Equal(t, tt.expected, result)
		})
	}
}
