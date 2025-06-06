// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseManagement.Outputs
{

    [OutputType]
    public sealed class ExternalMySqlDatabaseConnectorConnectorDetails
    {
        /// <summary>
        /// (Updatable) Type of the credential.
        /// </summary>
        public readonly string CredentialType;
        /// <summary>
        /// (Updatable) External MySQL Database Connector Name.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// (Updatable) OCID of MySQL Database resource.
        /// </summary>
        public readonly string ExternalDatabaseId;
        /// <summary>
        /// (Updatable) Host name for Connector.
        /// </summary>
        public readonly string HostName;
        /// <summary>
        /// (Updatable) Agent Id of the MACS agent.
        /// </summary>
        public readonly string MacsAgentId;
        /// <summary>
        /// (Updatable) Protocol to be used to connect to External MySQL Database; TCP, TCP with SSL or Socket.
        /// </summary>
        public readonly string NetworkProtocol;
        /// <summary>
        /// (Updatable) Port number to connect to External MySQL Database.
        /// </summary>
        public readonly int Port;
        /// <summary>
        /// (Updatable) If using existing SSL secret to connect, OCID for the secret resource.
        /// </summary>
        public readonly string SslSecretId;

        [OutputConstructor]
        private ExternalMySqlDatabaseConnectorConnectorDetails(
            string credentialType,

            string displayName,

            string externalDatabaseId,

            string hostName,

            string macsAgentId,

            string networkProtocol,

            int port,

            string sslSecretId)
        {
            CredentialType = credentialType;
            DisplayName = displayName;
            ExternalDatabaseId = externalDatabaseId;
            HostName = hostName;
            MacsAgentId = macsAgentId;
            NetworkProtocol = networkProtocol;
            Port = port;
            SslSecretId = sslSecretId;
        }
    }
}
