// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DevOps.Outputs
{

    [OutputType]
    public sealed class GetDeployEnvironmentsDeployEnvironmentCollectionItemNetworkChannelResult
    {
        /// <summary>
        /// Network channel type.
        /// </summary>
        public readonly string NetworkChannelType;
        /// <summary>
        /// An array of network security group OCIDs.
        /// </summary>
        public readonly ImmutableArray<string> NsgIds;
        /// <summary>
        /// The OCID of the subnet where VNIC resources will be created for private endpoint.
        /// </summary>
        public readonly string SubnetId;

        [OutputConstructor]
        private GetDeployEnvironmentsDeployEnvironmentCollectionItemNetworkChannelResult(
            string networkChannelType,

            ImmutableArray<string> nsgIds,

            string subnetId)
        {
            NetworkChannelType = networkChannelType;
            NsgIds = nsgIds;
            SubnetId = subnetId;
        }
    }
}