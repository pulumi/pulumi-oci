// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseManagement.Outputs
{

    [OutputType]
    public sealed class GetExternalDbSystemDiscoveryDiscoveredComponentNetworkConfigurationResult
    {
        /// <summary>
        /// The network number from which VIPs are obtained.
        /// </summary>
        public readonly int NetworkNumber;
        /// <summary>
        /// The network type.
        /// </summary>
        public readonly string NetworkType;
        /// <summary>
        /// The subnet for the network.
        /// </summary>
        public readonly string Subnet;

        [OutputConstructor]
        private GetExternalDbSystemDiscoveryDiscoveredComponentNetworkConfigurationResult(
            int networkNumber,

            string networkType,

            string subnet)
        {
            NetworkNumber = networkNumber;
            NetworkType = networkType;
            Subnet = subnet;
        }
    }
}
