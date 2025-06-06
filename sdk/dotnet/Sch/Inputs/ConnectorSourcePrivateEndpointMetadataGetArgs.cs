// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Sch.Inputs
{

    public sealed class ConnectorSourcePrivateEndpointMetadataGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The reverse connection endpoint (RCE) IP address for DNS lookups.
        /// </summary>
        [Input("rceDnsProxyIpAddress")]
        public Input<string>? RceDnsProxyIpAddress { get; set; }

        /// <summary>
        /// The reverse connection endpoint (RCE) IP address for primary flow of traffic in the subnet.
        /// </summary>
        [Input("rceTrafficIpAddress")]
        public Input<string>? RceTrafficIpAddress { get; set; }

        public ConnectorSourcePrivateEndpointMetadataGetArgs()
        {
        }
        public static new ConnectorSourcePrivateEndpointMetadataGetArgs Empty => new ConnectorSourcePrivateEndpointMetadataGetArgs();
    }
}
