// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core.Outputs
{

    [OutputType]
    public sealed class VnicAttachmentCreateVnicDetailsIpv6addressIpv6subnetCidrPairDetail
    {
        public readonly string? Ipv6Address;
        public readonly string? Ipv6SubnetCidr;

        [OutputConstructor]
        private VnicAttachmentCreateVnicDetailsIpv6addressIpv6subnetCidrPairDetail(
            string? ipv6Address,

            string? ipv6SubnetCidr)
        {
            Ipv6Address = ipv6Address;
            Ipv6SubnetCidr = ipv6SubnetCidr;
        }
    }
}
