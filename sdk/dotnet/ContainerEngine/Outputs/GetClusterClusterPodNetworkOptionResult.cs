// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ContainerEngine.Outputs
{

    [OutputType]
    public sealed class GetClusterClusterPodNetworkOptionResult
    {
        /// <summary>
        /// The CNI used by the node pools of this cluster
        /// </summary>
        public readonly string CniType;

        [OutputConstructor]
        private GetClusterClusterPodNetworkOptionResult(string cniType)
        {
            CniType = cniType;
        }
    }
}
