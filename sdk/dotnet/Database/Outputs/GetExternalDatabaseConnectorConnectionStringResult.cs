// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database.Outputs
{

    [OutputType]
    public sealed class GetExternalDatabaseConnectorConnectionStringResult
    {
        /// <summary>
        /// The host name of the database.
        /// </summary>
        public readonly string Hostname;
        /// <summary>
        /// The port used to connect to the database.
        /// </summary>
        public readonly int Port;
        /// <summary>
        /// The protocol used to connect to the database.
        /// </summary>
        public readonly string Protocol;
        /// <summary>
        /// The name of the service alias used to connect to the database.
        /// </summary>
        public readonly string Service;

        [OutputConstructor]
        private GetExternalDatabaseConnectorConnectionStringResult(
            string hostname,

            int port,

            string protocol,

            string service)
        {
            Hostname = hostname;
            Port = port;
            Protocol = protocol;
            Service = service;
        }
    }
}
