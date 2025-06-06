// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ContainerEngine.Inputs
{

    public sealed class ClusterClusterPodNetworkOptionGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The CNI used by the node pools of this cluster
        /// </summary>
        [Input("cniType", required: true)]
        public Input<string> CniType { get; set; } = null!;

        public ClusterClusterPodNetworkOptionGetArgs()
        {
        }
        public static new ClusterClusterPodNetworkOptionGetArgs Empty => new ClusterClusterPodNetworkOptionGetArgs();
    }
}
