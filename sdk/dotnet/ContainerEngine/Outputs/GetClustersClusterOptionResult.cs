// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ContainerEngine.Outputs
{

    [OutputType]
    public sealed class GetClustersClusterOptionResult
    {
        /// <summary>
        /// Configurable cluster add-ons
        /// </summary>
        public readonly ImmutableArray<Outputs.GetClustersClusterOptionAddOnResult> AddOns;
        /// <summary>
        /// Configurable cluster admission controllers
        /// </summary>
        public readonly ImmutableArray<Outputs.GetClustersClusterOptionAdmissionControllerOptionResult> AdmissionControllerOptions;
        /// <summary>
        /// Network configuration for Kubernetes.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetClustersClusterOptionKubernetesNetworkConfigResult> KubernetesNetworkConfigs;
        /// <summary>
        /// Configuration to be applied to block volumes created by Kubernetes Persistent Volume Claims (PVC)
        /// </summary>
        public readonly ImmutableArray<Outputs.GetClustersClusterOptionPersistentVolumeConfigResult> PersistentVolumeConfigs;
        /// <summary>
        /// Configuration to be applied to load balancers created by Kubernetes services
        /// </summary>
        public readonly ImmutableArray<Outputs.GetClustersClusterOptionServiceLbConfigResult> ServiceLbConfigs;
        /// <summary>
        /// The OCIDs of the subnets used for Kubernetes services load balancers.
        /// </summary>
        public readonly ImmutableArray<string> ServiceLbSubnetIds;

        [OutputConstructor]
        private GetClustersClusterOptionResult(
            ImmutableArray<Outputs.GetClustersClusterOptionAddOnResult> addOns,

            ImmutableArray<Outputs.GetClustersClusterOptionAdmissionControllerOptionResult> admissionControllerOptions,

            ImmutableArray<Outputs.GetClustersClusterOptionKubernetesNetworkConfigResult> kubernetesNetworkConfigs,

            ImmutableArray<Outputs.GetClustersClusterOptionPersistentVolumeConfigResult> persistentVolumeConfigs,

            ImmutableArray<Outputs.GetClustersClusterOptionServiceLbConfigResult> serviceLbConfigs,

            ImmutableArray<string> serviceLbSubnetIds)
        {
            AddOns = addOns;
            AdmissionControllerOptions = admissionControllerOptions;
            KubernetesNetworkConfigs = kubernetesNetworkConfigs;
            PersistentVolumeConfigs = persistentVolumeConfigs;
            ServiceLbConfigs = serviceLbConfigs;
            ServiceLbSubnetIds = serviceLbSubnetIds;
        }
    }
}