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
    public sealed class ExternalDbSystemDiscoveryPatchOperationValueConnector
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management agent used for the external DB system discovery.
        /// </summary>
        public readonly string? AgentId;
        /// <summary>
        /// The connection details required to connect to an external DB system component.
        /// </summary>
        public readonly Outputs.ExternalDbSystemDiscoveryPatchOperationValueConnectorConnectionInfo? ConnectionInfo;
        /// <summary>
        /// The type of connector.
        /// </summary>
        public readonly string ConnectorType;
        /// <summary>
        /// (Updatable) The user-friendly name for the DB system. The name does not have to be unique.
        /// </summary>
        public readonly string DisplayName;

        [OutputConstructor]
        private ExternalDbSystemDiscoveryPatchOperationValueConnector(
            string? agentId,

            Outputs.ExternalDbSystemDiscoveryPatchOperationValueConnectorConnectionInfo? connectionInfo,

            string connectorType,

            string displayName)
        {
            AgentId = agentId;
            ConnectionInfo = connectionInfo;
            ConnectorType = connectorType;
            DisplayName = displayName;
        }
    }
}
