// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Dns.Inputs
{

    public sealed class ZoneDnssecConfigKskDnssecKeyVersionDsDataArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The type of the digest associated with the rdata.
        /// </summary>
        [Input("digestType")]
        public Input<string>? DigestType { get; set; }

        /// <summary>
        /// Presentation-format DS record data that must be added to the parent zone. For more information about RDATA, see [Supported DNS Resource Record Types](https://docs.cloud.oracle.com/iaas/Content/DNS/Reference/supporteddnsresource.htm)
        /// </summary>
        [Input("rdata")]
        public Input<string>? Rdata { get; set; }

        public ZoneDnssecConfigKskDnssecKeyVersionDsDataArgs()
        {
        }
        public static new ZoneDnssecConfigKskDnssecKeyVersionDsDataArgs Empty => new ZoneDnssecConfigKskDnssecKeyVersionDsDataArgs();
    }
}
