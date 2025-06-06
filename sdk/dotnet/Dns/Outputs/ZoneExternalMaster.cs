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
    public sealed class ZoneExternalMaster
    {
        /// <summary>
        /// (Updatable) The server's IP address (IPv4 or IPv6).
        /// </summary>
        public readonly string Address;
        /// <summary>
        /// (Updatable) The server's port. Port value must be a value of 53, otherwise omit the port value.
        /// </summary>
        public readonly int? Port;
        /// <summary>
        /// (Updatable) The OCID of the TSIG key.
        /// </summary>
        public readonly string? TsigKeyId;

        [OutputConstructor]
        private ZoneExternalMaster(
            string address,

            int? port,

            string? tsigKeyId)
        {
            Address = address;
            Port = port;
            TsigKeyId = tsigKeyId;
        }
    }
}
