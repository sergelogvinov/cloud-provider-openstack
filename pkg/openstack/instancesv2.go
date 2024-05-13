/*
Copyright 2023 The Kubernetes Authors.

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
	"context"
	"fmt"
	sysos "os"
	"slices"
	"strings"

	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/servers"
	v1 "k8s.io/api/core/v1"
	cloudprovider "k8s.io/cloud-provider"
	"k8s.io/cloud-provider-openstack/pkg/client"
	"k8s.io/cloud-provider-openstack/pkg/metrics"
	"k8s.io/cloud-provider-openstack/pkg/util/errors"
	"k8s.io/klog/v2"
)

// InstancesV2 encapsulates an implementation of InstancesV2 for OpenStack.
type InstancesV2 struct {
	compute          map[string]*gophercloud.ServiceClient
	network          map[string]*gophercloud.ServiceClient
	regions          []string
	regionProviderID bool
	networkingOpts   NetworkingOpts
}

// InstancesV2 returns an implementation of InstancesV2 for OpenStack.
func (os *OpenStack) InstancesV2() (cloudprovider.InstancesV2, bool) {
	if !os.useV1Instances {
		return os.instancesv2()
	}
	return nil, false
}

func (os *OpenStack) instancesv2() (*InstancesV2, bool) {
	klog.V(4).Info("openstack.Instancesv2() called")

	var err error
	compute := make(map[string]*gophercloud.ServiceClient, len(os.regions))
	network := make(map[string]*gophercloud.ServiceClient, len(os.regions))

	for _, region := range os.regions {
		opt := os.epOpts
		opt.Region = region

		compute[region], err = client.NewComputeV2(os.provider, opt)
		if err != nil {
			klog.Errorf("unable to access compute v2 API : %v", err)
			return nil, false
		}

		network[region], err = client.NewNetworkV2(os.provider, opt)
		if err != nil {
			klog.Errorf("unable to access network v2 API : %v", err)
			return nil, false
		}
	}

	regionalProviderID := false
	if isRegionalProviderID := sysos.Getenv(RegionalProviderIDEnv); isRegionalProviderID == "true" {
		regionalProviderID = true
	}

	return &InstancesV2{
		compute:          compute,
		network:          network,
		regions:          os.regions,
		regionProviderID: regionalProviderID,
		networkingOpts:   os.networkingOpts,
	}, true
}

// InstanceExists indicates whether a given node exists according to the cloud provider
func (i *InstancesV2) InstanceExists(ctx context.Context, node *v1.Node) (bool, error) {
	if i.regionProviderID {
		if node.Spec.ProviderID == "" {
			klog.V(4).Infof("Instance %s should initialized first", node.Name)
			return true, nil
		}

		if instanceNodeUnmanaged(node.Spec.ProviderID) {
			klog.V(4).Infof("Instance %s is not an OpenStack instance", node.Name)
			return true, nil
		}
	}

	_, _, err := i.getInstance(ctx, node)
	if err == cloudprovider.InstanceNotFound {
		klog.V(6).Infof("instance not found for node: %s", node.Name)
		return false, nil
	}

	if err != nil {
		return false, err
	}

	return true, nil
}

// InstanceShutdown returns true if the instance is shutdown according to the cloud provider.
func (i *InstancesV2) InstanceShutdown(ctx context.Context, node *v1.Node) (bool, error) {
	if i.regionProviderID {
		if node.Spec.ProviderID == "" {
			klog.V(4).Infof("Instance %s should initialized first", node.Name)
			return false, nil
		}

		if instanceNodeUnmanaged(node.Spec.ProviderID) {
			klog.V(4).Infof("Instance %s is not an OpenStack instance", node.Name)
			return false, nil
		}
	}

	server, _, err := i.getInstance(ctx, node)
	if err != nil {
		return false, err
	}

	// SHUTOFF is the only state where we can detach volumes immediately
	if server.Status == instanceShutoff {
		return true, nil
	}

	return false, nil
}

// InstanceMetadata returns the instance's metadata.
func (i *InstancesV2) InstanceMetadata(ctx context.Context, node *v1.Node) (*cloudprovider.InstanceMetadata, error) {
	if node.Spec.ProviderID != "" && instanceNodeUnmanaged(node.Spec.ProviderID) {
		klog.V(4).Infof("Instance %s is not an OpenStack instance", node.Name)
		return &cloudprovider.InstanceMetadata{}, nil
	}

	srv, region, err := i.getInstance(ctx, node)
	if err != nil {
		return nil, err
	}
	server := ServerAttributesExt{}
	if srv != nil {
		server = *srv
	}

	instanceType, err := srvInstanceType(i.compute[region], &server.Server)
	if err != nil {
		return nil, err
	}

	ports, err := getAttachedPorts(i.network[region], server.ID)
	if err != nil {
		return nil, err
	}

	addresses, err := nodeAddresses(&server.Server, ports, i.network[region], i.networkingOpts)
	if err != nil {
		return nil, err
	}

	return &cloudprovider.InstanceMetadata{
		ProviderID:    i.makeInstanceID(&server.Server, region),
		InstanceType:  instanceType,
		NodeAddresses: addresses,
		Zone:          server.AvailabilityZone,
		Region:        region,
	}, nil
}

func (i *InstancesV2) makeInstanceID(srv *servers.Server, region string) string {
	if i.regionProviderID {
		return fmt.Sprintf("%s://%s/%s", ProviderName, region, srv.ID)
	}
	return fmt.Sprintf("%s:///%s", ProviderName, srv.ID)
}

func (i *InstancesV2) getInstance(ctx context.Context, node *v1.Node) (*ServerAttributesExt, string, error) {
	if node.Spec.ProviderID == "" {
		opt := servers.ListOpts{
			Name: fmt.Sprintf("^%s$", node.Name),
		}
		mc := metrics.NewMetricContext("server", "list")
		serverList := []ServerAttributesExt{}

		for _, r := range i.regions {
			allPages, err := servers.List(i.compute[r], opt).AllPages()
			if mc.ObserveRequest(err) != nil {
				return nil, "", fmt.Errorf("error listing servers %v: %v", opt, err)
			}

			err = servers.ExtractServersInto(allPages, &serverList)
			if err != nil {
				return nil, "", fmt.Errorf("error extracting servers from pages: %v", err)
			}
			if len(serverList) == 0 {
				continue
			}
			if len(serverList) > 1 {
				return nil, "", fmt.Errorf("getInstance: multiple instances found")
			}

			return &serverList[0], r, nil
		}

		return nil, "", cloudprovider.InstanceNotFound
	}

	instanceID, instanceRegion, err := instanceIDFromProviderID(node.Spec.ProviderID)
	if err != nil {
		return nil, "", err
	}

	if instanceRegion == "" {
		instanceRegion = i.regions[0]
	}

	if !slices.Contains(i.regions, instanceRegion) {
		return nil, "", fmt.Errorf("getInstance: ProviderID %s didn't match supported region %s", node.Spec.ProviderID, strings.Join(i.regions, ","))
	}

	server := ServerAttributesExt{}
	mc := metrics.NewMetricContext("server", "get")
	err = servers.Get(i.compute[instanceRegion], instanceID).ExtractInto(&server)
	if mc.ObserveRequest(err) != nil {
		if errors.IsNotFound(err) {
			return nil, "", cloudprovider.InstanceNotFound
		}
		return nil, "", err
	}
	return &server, instanceRegion, nil
}
