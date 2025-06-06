// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Analytics.Inputs
{

    public sealed class AnalyticsInstanceNetworkEndpointDetailsGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The type of network endpoint.
        /// </summary>
        [Input("networkEndpointType", required: true)]
        public Input<string> NetworkEndpointType { get; set; } = null!;

        [Input("networkSecurityGroupIds")]
        private InputList<string>? _networkSecurityGroupIds;

        /// <summary>
        /// Network Security Group OCIDs for an Analytics instance.
        /// </summary>
        public InputList<string> NetworkSecurityGroupIds
        {
            get => _networkSecurityGroupIds ?? (_networkSecurityGroupIds = new InputList<string>());
            set => _networkSecurityGroupIds = value;
        }

        /// <summary>
        /// The subnet OCID for the private endpoint.
        /// </summary>
        [Input("subnetId")]
        public Input<string>? SubnetId { get; set; }

        /// <summary>
        /// The VCN OCID for the private endpoint.
        /// </summary>
        [Input("vcnId")]
        public Input<string>? VcnId { get; set; }

        [Input("whitelistedIps")]
        private InputList<string>? _whitelistedIps;

        /// <summary>
        /// Source IP addresses or IP address ranges in ingress rules.
        /// </summary>
        public InputList<string> WhitelistedIps
        {
            get => _whitelistedIps ?? (_whitelistedIps = new InputList<string>());
            set => _whitelistedIps = value;
        }

        [Input("whitelistedServices")]
        private InputList<string>? _whitelistedServices;

        /// <summary>
        /// Oracle Cloud Services that are allowed to access this Analytics instance.
        /// </summary>
        public InputList<string> WhitelistedServices
        {
            get => _whitelistedServices ?? (_whitelistedServices = new InputList<string>());
            set => _whitelistedServices = value;
        }

        [Input("whitelistedVcns")]
        private InputList<Inputs.AnalyticsInstanceNetworkEndpointDetailsWhitelistedVcnGetArgs>? _whitelistedVcns;

        /// <summary>
        /// Virtual Cloud Networks allowed to access this network endpoint.
        /// </summary>
        public InputList<Inputs.AnalyticsInstanceNetworkEndpointDetailsWhitelistedVcnGetArgs> WhitelistedVcns
        {
            get => _whitelistedVcns ?? (_whitelistedVcns = new InputList<Inputs.AnalyticsInstanceNetworkEndpointDetailsWhitelistedVcnGetArgs>());
            set => _whitelistedVcns = value;
        }

        public AnalyticsInstanceNetworkEndpointDetailsGetArgs()
        {
        }
        public static new AnalyticsInstanceNetworkEndpointDetailsGetArgs Empty => new AnalyticsInstanceNetworkEndpointDetailsGetArgs();
    }
}
