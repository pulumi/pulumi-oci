// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core.Inputs
{

    public sealed class InstanceCreateVnicDetailsIpv6addressIpv6subnetCidrPairDetailArgs : global::Pulumi.ResourceArgs
    {
        [Input("ipv6address")]
        public Input<string>? Ipv6address { get; set; }

        [Input("ipv6subnetCidr")]
        public Input<string>? Ipv6subnetCidr { get; set; }

        public InstanceCreateVnicDetailsIpv6addressIpv6subnetCidrPairDetailArgs()
        {
        }
        public static new InstanceCreateVnicDetailsIpv6addressIpv6subnetCidrPairDetailArgs Empty => new InstanceCreateVnicDetailsIpv6addressIpv6subnetCidrPairDetailArgs();
    }
}