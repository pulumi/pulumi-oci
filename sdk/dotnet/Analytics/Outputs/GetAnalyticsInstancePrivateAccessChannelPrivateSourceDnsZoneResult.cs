// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Analytics.Outputs
{

    [OutputType]
    public sealed class GetAnalyticsInstancePrivateAccessChannelPrivateSourceDnsZoneResult
    {
        /// <summary>
        /// Description of private source scan host zone.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// Private Source DNS Zone. Ex: example-vcn.oraclevcn.com, corp.example.com.
        /// </summary>
        public readonly string DnsZone;

        [OutputConstructor]
        private GetAnalyticsInstancePrivateAccessChannelPrivateSourceDnsZoneResult(
            string description,

            string dnsZone)
        {
            Description = description;
            DnsZone = dnsZone;
        }
    }
}
