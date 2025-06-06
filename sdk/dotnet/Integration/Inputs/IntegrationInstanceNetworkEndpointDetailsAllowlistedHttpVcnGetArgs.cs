// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Integration.Inputs
{

    public sealed class IntegrationInstanceNetworkEndpointDetailsAllowlistedHttpVcnGetArgs : global::Pulumi.ResourceArgs
    {
        [Input("allowlistedIps")]
        private InputList<string>? _allowlistedIps;

        /// <summary>
        /// Source IP addresses or IP address ranges ingress rules. (ex: "168.122.59.5", "10.20.30.0/26") An invalid IP or CIDR block will result in a 400 response.
        /// </summary>
        public InputList<string> AllowlistedIps
        {
            get => _allowlistedIps ?? (_allowlistedIps = new InputList<string>());
            set => _allowlistedIps = value;
        }

        /// <summary>
        /// The Virtual Cloud Network OCID.
        /// </summary>
        [Input("id", required: true)]
        public Input<string> Id { get; set; } = null!;

        public IntegrationInstanceNetworkEndpointDetailsAllowlistedHttpVcnGetArgs()
        {
        }
        public static new IntegrationInstanceNetworkEndpointDetailsAllowlistedHttpVcnGetArgs Empty => new IntegrationInstanceNetworkEndpointDetailsAllowlistedHttpVcnGetArgs();
    }
}
