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
    public sealed class ClusterOptions
    {
        /// <summary>
        /// Configurable cluster add-ons
        /// </summary>
        public readonly Outputs.ClusterOptionsAddOns? AddOns;
        /// <summary>
        /// (Updatable) Configurable cluster admission controllers
        /// </summary>
        public readonly Outputs.ClusterOptionsAdmissionControllerOptions? AdmissionControllerOptions;
        /// <summary>
        /// Network configuration for Kubernetes.
        /// </summary>
        public readonly Outputs.ClusterOptionsKubernetesNetworkConfig? KubernetesNetworkConfig;
        /// <summary>
        /// (Updatable) Configuration to be applied to block volumes created by Kubernetes Persistent Volume Claims (PVC)
        /// </summary>
        public readonly Outputs.ClusterOptionsPersistentVolumeConfig? PersistentVolumeConfig;
        /// <summary>
        /// (Updatable) Configuration to be applied to load balancers created by Kubernetes services
        /// </summary>
        public readonly Outputs.ClusterOptionsServiceLbConfig? ServiceLbConfig;
        /// <summary>
        /// The OCIDs of the subnets used for Kubernetes services load balancers.
        /// </summary>
        public readonly ImmutableArray<string> ServiceLbSubnetIds;

        [OutputConstructor]
        private ClusterOptions(
            Outputs.ClusterOptionsAddOns? addOns,

            Outputs.ClusterOptionsAdmissionControllerOptions? admissionControllerOptions,

            Outputs.ClusterOptionsKubernetesNetworkConfig? kubernetesNetworkConfig,

            Outputs.ClusterOptionsPersistentVolumeConfig? persistentVolumeConfig,

            Outputs.ClusterOptionsServiceLbConfig? serviceLbConfig,

            ImmutableArray<string> serviceLbSubnetIds)
        {
            AddOns = addOns;
            AdmissionControllerOptions = admissionControllerOptions;
            KubernetesNetworkConfig = kubernetesNetworkConfig;
            PersistentVolumeConfig = persistentVolumeConfig;
            ServiceLbConfig = serviceLbConfig;
            ServiceLbSubnetIds = serviceLbSubnetIds;
        }
    }
}