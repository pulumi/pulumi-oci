// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Waas.Outputs
{

    [OutputType]
    public sealed class GetEdgeSubnetsEdgeSubnetResult
    {
        /// <summary>
        /// An edge node subnet. This can include /24 or /8 addresses.
        /// </summary>
        public readonly string Cidr;
        /// <summary>
        /// The name of the region containing the indicated subnet.
        /// </summary>
        public readonly string Region;
        /// <summary>
        /// The date and time the last change was made to the indicated edge node subnet, expressed in RFC 3339 timestamp format.
        /// </summary>
        public readonly string TimeModified;

        [OutputConstructor]
        private GetEdgeSubnetsEdgeSubnetResult(
            string cidr,

            string region,

            string timeModified)
        {
            Cidr = cidr;
            Region = region;
            TimeModified = timeModified;
        }
    }
}
