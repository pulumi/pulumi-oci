// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ContainerEngine.Inputs
{

    public sealed class ClusterOptionsArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// Configurable cluster add-ons
        /// </summary>
        [Input("addOns")]
        public Input<Inputs.ClusterOptionsAddOnsArgs>? AddOns { get; set; }

        /// <summary>
        /// (Updatable) Configurable cluster admission controllers
        /// </summary>
        [Input("admissionControllerOptions")]
        public Input<Inputs.ClusterOptionsAdmissionControllerOptionsArgs>? AdmissionControllerOptions { get; set; }

        /// <summary>
        /// Network configuration for Kubernetes.
        /// </summary>
        [Input("kubernetesNetworkConfig")]
        public Input<Inputs.ClusterOptionsKubernetesNetworkConfigArgs>? KubernetesNetworkConfig { get; set; }

        /// <summary>
        /// (Updatable) Configuration to be applied to block volumes created by Kubernetes Persistent Volume Claims (PVC)
        /// </summary>
        [Input("persistentVolumeConfig")]
        public Input<Inputs.ClusterOptionsPersistentVolumeConfigArgs>? PersistentVolumeConfig { get; set; }

        /// <summary>
        /// (Updatable) Configuration to be applied to load balancers created by Kubernetes services
        /// </summary>
        [Input("serviceLbConfig")]
        public Input<Inputs.ClusterOptionsServiceLbConfigArgs>? ServiceLbConfig { get; set; }

        [Input("serviceLbSubnetIds")]
        private InputList<string>? _serviceLbSubnetIds;

        /// <summary>
        /// The OCIDs of the subnets used for Kubernetes services load balancers.
        /// </summary>
        public InputList<string> ServiceLbSubnetIds
        {
            get => _serviceLbSubnetIds ?? (_serviceLbSubnetIds = new InputList<string>());
            set => _serviceLbSubnetIds = value;
        }

        public ClusterOptionsArgs()
        {
        }
        public static new ClusterOptionsArgs Empty => new ClusterOptionsArgs();
    }
}