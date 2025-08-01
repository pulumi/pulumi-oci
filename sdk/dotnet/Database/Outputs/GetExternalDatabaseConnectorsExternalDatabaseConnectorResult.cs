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
    public sealed class GetExternalDatabaseConnectorsExternalDatabaseConnectorResult
    {
        /// <summary>
        /// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Credentials used to connect to the database. Currently only the `DETAILS` type is supported for creating MACS connector crendentials.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetExternalDatabaseConnectorsExternalDatabaseConnectorConnectionCredentialResult> ConnectionCredentials;
        /// <summary>
        /// The status of connectivity to the external database.
        /// </summary>
        public readonly string ConnectionStatus;
        /// <summary>
        /// The Oracle Database connection string.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetExternalDatabaseConnectorsExternalDatabaseConnectorConnectionStringResult> ConnectionStrings;
        /// <summary>
        /// The ID of the agent used for the [external database connector](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalDatabaseConnectorDetails).
        /// </summary>
        public readonly string ConnectorAgentId;
        /// <summary>
        /// The type of connector used by the external database resource.
        /// </summary>
        public readonly string ConnectorType;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// A filter to return only resources that match the entire display name given. The match is not case sensitive.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external database whose connectors will be listed.
        /// </summary>
        public readonly string ExternalDatabaseId;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the [external database connector](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalDatabaseConnectorDetails).
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Additional information about the current lifecycle state.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// A filter to return only resources that match the specified lifecycle state.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        /// </summary>
        public readonly ImmutableDictionary<string, string> SystemTags;
        /// <summary>
        /// The date and time the `connectionStatus` of this external connector was last updated.
        /// </summary>
        public readonly string TimeConnectionStatusLastUpdated;
        /// <summary>
        /// The date and time the external connector was created.
        /// </summary>
        public readonly string TimeCreated;

        [OutputConstructor]
        private GetExternalDatabaseConnectorsExternalDatabaseConnectorResult(
            string compartmentId,

            ImmutableArray<Outputs.GetExternalDatabaseConnectorsExternalDatabaseConnectorConnectionCredentialResult> connectionCredentials,

            string connectionStatus,

            ImmutableArray<Outputs.GetExternalDatabaseConnectorsExternalDatabaseConnectorConnectionStringResult> connectionStrings,

            string connectorAgentId,

            string connectorType,

            ImmutableDictionary<string, string> definedTags,

            string displayName,

            string externalDatabaseId,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            string lifecycleDetails,

            string state,

            ImmutableDictionary<string, string> systemTags,

            string timeConnectionStatusLastUpdated,

            string timeCreated)
        {
            CompartmentId = compartmentId;
            ConnectionCredentials = connectionCredentials;
            ConnectionStatus = connectionStatus;
            ConnectionStrings = connectionStrings;
            ConnectorAgentId = connectorAgentId;
            ConnectorType = connectorType;
            DefinedTags = definedTags;
            DisplayName = displayName;
            ExternalDatabaseId = externalDatabaseId;
            FreeformTags = freeformTags;
            Id = id;
            LifecycleDetails = lifecycleDetails;
            State = state;
            SystemTags = systemTags;
            TimeConnectionStatusLastUpdated = timeConnectionStatusLastUpdated;
            TimeCreated = timeCreated;
        }
    }
}
