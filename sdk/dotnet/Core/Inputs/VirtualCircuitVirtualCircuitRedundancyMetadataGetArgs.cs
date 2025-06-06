// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core.Inputs
{

    public sealed class VirtualCircuitVirtualCircuitRedundancyMetadataGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The configured redundancy level of the virtual circuit.
        /// </summary>
        [Input("configuredRedundancyLevel")]
        public Input<string>? ConfiguredRedundancyLevel { get; set; }

        /// <summary>
        /// Indicates if the configured level is met for IPv4 BGP redundancy.
        /// </summary>
        [Input("ipv4bgpSessionRedundancyStatus")]
        public Input<string>? Ipv4bgpSessionRedundancyStatus { get; set; }

        /// <summary>
        /// Indicates if the configured level is met for IPv6 BGP redundancy.
        /// </summary>
        [Input("ipv6bgpSessionRedundancyStatus")]
        public Input<string>? Ipv6bgpSessionRedundancyStatus { get; set; }

        public VirtualCircuitVirtualCircuitRedundancyMetadataGetArgs()
        {
        }
        public static new VirtualCircuitVirtualCircuitRedundancyMetadataGetArgs Empty => new VirtualCircuitVirtualCircuitRedundancyMetadataGetArgs();
    }
}
