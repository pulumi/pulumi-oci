// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Dns.Outputs
{

    [OutputType]
    public sealed class ZoneZoneTransferServer
    {
        /// <summary>
        /// (Updatable) The server's IP address (IPv4 or IPv6).
        /// </summary>
        public readonly string? Address;
        /// <summary>
        /// A Boolean flag indicating whether or not the server is a zone data transfer destination.
        /// </summary>
        public readonly bool? IsTransferDestination;
        /// <summary>
        /// A Boolean flag indicating whether or not the server is a zone data transfer source.
        /// </summary>
        public readonly bool? IsTransferSource;
        /// <summary>
        /// (Updatable) The server's port. Port value must be a value of 53, otherwise omit the port value.
        /// </summary>
        public readonly int? Port;

        [OutputConstructor]
        private ZoneZoneTransferServer(
            string? address,

            bool? isTransferDestination,

            bool? isTransferSource,

            int? port)
        {
            Address = address;
            IsTransferDestination = isTransferDestination;
            IsTransferSource = isTransferSource;
            Port = port;
        }
    }
}