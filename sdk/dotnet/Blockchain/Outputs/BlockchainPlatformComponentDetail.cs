// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Blockchain.Outputs
{

    [OutputType]
    public sealed class BlockchainPlatformComponentDetail
    {
        /// <summary>
        /// List of OSNs
        /// </summary>
        public readonly ImmutableArray<Outputs.BlockchainPlatformComponentDetailOsn> Osns;
        /// <summary>
        /// List of Peers
        /// </summary>
        public readonly ImmutableArray<Outputs.BlockchainPlatformComponentDetailPeer> Peers;

        [OutputConstructor]
        private BlockchainPlatformComponentDetail(
            ImmutableArray<Outputs.BlockchainPlatformComponentDetailOsn> osns,

            ImmutableArray<Outputs.BlockchainPlatformComponentDetailPeer> peers)
        {
            Osns = osns;
            Peers = peers;
        }
    }
}