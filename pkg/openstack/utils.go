/*
Copyright 2014 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package openstack

import (
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"

	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/flavors"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/servers"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/networks"
	neutronports "github.com/gophercloud/gophercloud/openstack/networking/v2/ports"
	"github.com/mitchellh/mapstructure"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/cloud-provider-openstack/pkg/metrics"
	"k8s.io/cloud-provider-openstack/pkg/util"
	"k8s.io/klog/v2"
)

// If Instances.InstanceID or cloudprovider.GetInstanceProviderID is changed, the regexp should be changed too.
var providerIDRegexp = regexp.MustCompile(`^` + ProviderName + `://([^/]*)/([^/]+)$`)

// instanceIDFromProviderID splits a provider's id and return instanceID.
// A providerID is build out of '${ProviderName}:///${instance-id}' which contains ':///'.
// or '${ProviderName}://${region}/${instance-id}' which contains '://'.
// See cloudprovider.GetInstanceProviderID and Instances.InstanceID.
func instanceIDFromProviderID(providerID string) (instanceID string, region string, err error) {

	// https://github.com/kubernetes/kubernetes/issues/85731
	if providerID != "" && !strings.Contains(providerID, "://") {
		providerID = ProviderName + "://" + providerID
	}

	matches := providerIDRegexp.FindStringSubmatch(providerID)
	if len(matches) != 3 {
		return "", "", fmt.Errorf("ProviderID \"%s\" didn't match expected format \"openstack://region/InstanceID\"", providerID)
	}
	return matches[2], matches[1], nil
}

func instanceNodeUnmanaged(providerID string) bool {
	if providerID != "" &&
		strings.Contains(providerID, "://") &&
		!strings.HasPrefix(providerID, ProviderName+"://") {
		return true
	}

	return false
}

func srvInstanceType(client *gophercloud.ServiceClient, srv *servers.Server) (string, error) {
	keys := []string{"original_name", "id"}
	for _, key := range keys {
		val, found := srv.Flavor[key]
		if !found {
			continue
		}

		flavor, ok := val.(string)
		if !ok {
			continue
		}

		if key == "original_name" && isValidLabelValue(flavor) {
			return flavor, nil
		}

		// get flavor name by id
		mc := metrics.NewMetricContext("flavor", "get")
		f, err := flavors.Get(client, flavor).Extract()
		if mc.ObserveRequest(err) == nil {
			if isValidLabelValue(f.Name) {
				return f.Name, nil
			}
			// fallback on flavor id
			return f.ID, nil
		}
	}
	return "", fmt.Errorf("flavor original_name/id not found")
}

func isValidLabelValue(v string) bool {
	if errs := validation.IsValidLabelValue(v); len(errs) != 0 {
		return false
	}
	return true
}

// getAttachedPorts returns a list of ports attached to a server.
func getAttachedPorts(client *gophercloud.ServiceClient, serverID string) ([]PortWithTrunkDetails, error) {
	listOpts := neutronports.ListOpts{
		DeviceID: serverID,
	}

	var ports []PortWithTrunkDetails

	allPages, err := neutronports.List(client, listOpts).AllPages()
	if err != nil {
		return ports, err
	}
	err = neutronports.ExtractPortsInto(allPages, &ports)
	if err != nil {
		return ports, err
	}

	return ports, nil
}

// IP addresses order:
// * interfaces private IPs
// * access IPs
// * metadata hostname
// * server object Addresses (floating type)
func nodeAddresses(srv *servers.Server, ports []PortWithTrunkDetails, client *gophercloud.ServiceClient, networkingOpts NetworkingOpts) ([]v1.NodeAddress, error) {
	addrs := []v1.NodeAddress{}

	// parse private IP addresses first in an ordered manner
	for _, port := range ports {
		for _, fixedIP := range port.FixedIPs {
			if port.Status == "ACTIVE" {
				isIPv6 := net.ParseIP(fixedIP.IPAddress).To4() == nil
				if !(isIPv6 && networkingOpts.IPv6SupportDisabled) {
					AddToNodeAddresses(&addrs,
						v1.NodeAddress{
							Type:    v1.NodeInternalIP,
							Address: fixedIP.IPAddress,
						},
					)
				}
			}
		}
	}

	// process public IP addresses
	if srv.AccessIPv4 != "" {
		AddToNodeAddresses(&addrs,
			v1.NodeAddress{
				Type:    v1.NodeExternalIP,
				Address: srv.AccessIPv4,
			},
		)
	}

	if srv.AccessIPv6 != "" && !networkingOpts.IPv6SupportDisabled {
		AddToNodeAddresses(&addrs,
			v1.NodeAddress{
				Type:    v1.NodeExternalIP,
				Address: srv.AccessIPv6,
			},
		)
	}

	if srv.Metadata[TypeHostName] != "" {
		AddToNodeAddresses(&addrs,
			v1.NodeAddress{
				Type:    v1.NodeHostName,
				Address: srv.Metadata[TypeHostName],
			},
		)
	}

	// process the rest
	type Address struct {
		IPType string `mapstructure:"OS-EXT-IPS:type"`
		Addr   string
	}

	var addresses map[string][]Address
	err := mapstructure.Decode(srv.Addresses, &addresses)
	if err != nil {
		return nil, err
	}

	// Add the addresses assigned on subports via trunk
	// This exposes the vlan networks to which subports are attached
	for _, port := range ports {
		for _, subport := range port.TrunkDetails.SubPorts {
			p, err := neutronports.Get(client, subport.PortID).Extract()
			if err != nil {
				klog.Errorf("Failed to get subport %s details: %v", subport.PortID, err)
				continue
			}
			n, err := networks.Get(client, p.NetworkID).Extract()
			if err != nil {
				klog.Errorf("Failed to get subport %s network details: %v", subport.PortID, err)
				continue
			}
			for _, fixedIP := range p.FixedIPs {
				klog.V(5).Infof("Node '%s' is found subport '%s' address '%s/%s'", srv.Name, p.Name, n.Name, fixedIP.IPAddress)
				isIPv6 := net.ParseIP(fixedIP.IPAddress).To4() == nil
				if !(isIPv6 && networkingOpts.IPv6SupportDisabled) {
					addr := Address{IPType: "fixed", Addr: fixedIP.IPAddress}
					subportAddresses := map[string][]Address{n.Name: {addr}}
					srvAddresses, ok := addresses[n.Name]
					if !ok {
						addresses[n.Name] = subportAddresses[n.Name]
					} else {
						// this is to take care the corner case
						// where the same network is attached to the node both directly and via trunk
						addresses[n.Name] = append(srvAddresses, subportAddresses[n.Name]...)
					}
				}
			}
		}
	}

	networks := make([]string, 0, len(addresses))
	for k := range addresses {
		networks = append(networks, k)
	}
	sort.Strings(networks)

	for _, network := range networks {
		for _, props := range addresses[network] {
			var addressType v1.NodeAddressType
			if props.IPType == "floating" {
				addressType = v1.NodeExternalIP
			} else if util.Contains(networkingOpts.PublicNetworkName, network) {
				addressType = v1.NodeExternalIP
				// removing already added address to avoid listing it as both ExternalIP and InternalIP
				// may happen due to listing "private" network as "public" in CCM's config
				RemoveFromNodeAddresses(&addrs,
					v1.NodeAddress{
						Address: props.Addr,
					},
				)
			} else {
				if len(networkingOpts.InternalNetworkName) == 0 || util.Contains(networkingOpts.InternalNetworkName, network) {
					addressType = v1.NodeInternalIP
				} else {
					klog.V(5).Infof("Node '%s' address '%s' ignored due to 'internal-network-name' option", srv.Name, props.Addr)
					RemoveFromNodeAddresses(&addrs,
						v1.NodeAddress{
							Address: props.Addr,
						},
					)
					continue
				}
			}

			isIPv6 := net.ParseIP(props.Addr).To4() == nil
			if !(isIPv6 && networkingOpts.IPv6SupportDisabled) {
				AddToNodeAddresses(&addrs,
					v1.NodeAddress{
						Type:    addressType,
						Address: props.Addr,
					},
				)
			}
		}
	}

	if networkingOpts.AddressSortOrder != "" {
		sortNodeAddresses(addrs, networkingOpts.AddressSortOrder)
	}

	klog.V(5).Infof("Node '%s' returns addresses '%v'", srv.Name, addrs)
	return addrs, nil
}
