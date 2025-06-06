// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ComputeCloud.Inputs
{

    public sealed class AtCustomerCccInfrastructureInfrastructureNetworkConfigurationInfrastructureRoutingDynamicGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The topology in use for the Border Gateway Protocol (BGP) configuration.
        /// </summary>
        [Input("bgpTopology")]
        public Input<string>? BgpTopology { get; set; }

        /// <summary>
        /// The Oracle Autonomous System Number (ASN) to control routing and exchange information within the dynamic routing configuration.
        /// </summary>
        [Input("oracleAsn")]
        public Input<int>? OracleAsn { get; set; }

        [Input("peerInformations")]
        private InputList<Inputs.AtCustomerCccInfrastructureInfrastructureNetworkConfigurationInfrastructureRoutingDynamicPeerInformationGetArgs>? _peerInformations;

        /// <summary>
        /// The list of peer devices in the dynamic routing configuration.
        /// </summary>
        public InputList<Inputs.AtCustomerCccInfrastructureInfrastructureNetworkConfigurationInfrastructureRoutingDynamicPeerInformationGetArgs> PeerInformations
        {
            get => _peerInformations ?? (_peerInformations = new InputList<Inputs.AtCustomerCccInfrastructureInfrastructureNetworkConfigurationInfrastructureRoutingDynamicPeerInformationGetArgs>());
            set => _peerInformations = value;
        }

        public AtCustomerCccInfrastructureInfrastructureNetworkConfigurationInfrastructureRoutingDynamicGetArgs()
        {
        }
        public static new AtCustomerCccInfrastructureInfrastructureNetworkConfigurationInfrastructureRoutingDynamicGetArgs Empty => new AtCustomerCccInfrastructureInfrastructureNetworkConfigurationInfrastructureRoutingDynamicGetArgs();
    }
}
