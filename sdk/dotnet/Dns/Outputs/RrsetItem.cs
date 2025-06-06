// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Dns.Outputs
{

    [OutputType]
    public sealed class RrsetItem
    {
        /// <summary>
        /// The fully qualified domain name where the record can be located.
        /// </summary>
        public readonly string Domain;
        /// <summary>
        /// A Boolean flag indicating whether or not parts of the record are unable to be explicitly managed.
        /// </summary>
        public readonly bool? IsProtected;
        /// <summary>
        /// (Updatable) The record's data, as whitespace-delimited tokens in type-specific presentation format. All RDATA is normalized and the returned presentation of your RDATA may differ from its initial input. For more information about RDATA, see [Supported DNS Resource Record Types](https://docs.cloud.oracle.com/iaas/Content/DNS/Reference/supporteddnsresource.htm)
        /// </summary>
        public readonly string Rdata;
        /// <summary>
        /// A unique identifier for the record within its zone.
        /// </summary>
        public readonly string? RecordHash;
        /// <summary>
        /// The latest version of the record's zone in which its RRSet differs from the preceding version.
        /// </summary>
        public readonly string? RrsetVersion;
        /// <summary>
        /// The type of DNS record, such as A or CNAME. For more information, see [Resource Record (RR) TYPEs](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4).
        /// </summary>
        public readonly string Rtype;
        /// <summary>
        /// (Updatable) The Time To Live for the record, in seconds. Using a TTL lower than 30 seconds is not recommended.
        /// </summary>
        public readonly int Ttl;

        [OutputConstructor]
        private RrsetItem(
            string domain,

            bool? isProtected,

            string rdata,

            string? recordHash,

            string? rrsetVersion,

            string rtype,

            int ttl)
        {
            Domain = domain;
            IsProtected = isProtected;
            Rdata = rdata;
            RecordHash = recordHash;
            RrsetVersion = rrsetVersion;
            Rtype = rtype;
            Ttl = ttl;
        }
    }
}
