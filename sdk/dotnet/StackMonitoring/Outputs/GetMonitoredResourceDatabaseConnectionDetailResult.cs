// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.StackMonitoring.Outputs
{

    [OutputType]
    public sealed class GetMonitoredResourceDatabaseConnectionDetailResult
    {
        /// <summary>
        /// Database connector Identifier
        /// </summary>
        public readonly string ConnectorId;
        /// <summary>
        /// dbId of the database
        /// </summary>
        public readonly string DbId;
        /// <summary>
        /// UniqueName used for database connection requests.
        /// </summary>
        public readonly string DbUniqueName;
        /// <summary>
        /// Listener Port number used for connection requests.
        /// </summary>
        public readonly int Port;
        /// <summary>
        /// Protocol used in DB connection string when connecting to external database service.
        /// </summary>
        public readonly string Protocol;
        /// <summary>
        /// Service name used for connection requests.
        /// </summary>
        public readonly string ServiceName;

        [OutputConstructor]
        private GetMonitoredResourceDatabaseConnectionDetailResult(
            string connectorId,

            string dbId,

            string dbUniqueName,

            int port,

            string protocol,

            string serviceName)
        {
            ConnectorId = connectorId;
            DbId = dbId;
            DbUniqueName = dbUniqueName;
            Port = port;
            Protocol = protocol;
            ServiceName = serviceName;
        }
    }
}