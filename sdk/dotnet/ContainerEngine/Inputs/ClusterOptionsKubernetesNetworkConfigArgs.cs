// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ContainerEngine.Inputs
{

    public sealed class ClusterOptionsKubernetesNetworkConfigArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The CIDR block for Kubernetes pods. Optional, defaults to 10.244.0.0/16.
        /// </summary>
        [Input("podsCidr")]
        public Input<string>? PodsCidr { get; set; }

        /// <summary>
        /// The CIDR block for Kubernetes services. Optional, defaults to 10.96.0.0/16.
        /// </summary>
        [Input("servicesCidr")]
        public Input<string>? ServicesCidr { get; set; }

        public ClusterOptionsKubernetesNetworkConfigArgs()
        {
        }
        public static new ClusterOptionsKubernetesNetworkConfigArgs Empty => new ClusterOptionsKubernetesNetworkConfigArgs();
    }
}