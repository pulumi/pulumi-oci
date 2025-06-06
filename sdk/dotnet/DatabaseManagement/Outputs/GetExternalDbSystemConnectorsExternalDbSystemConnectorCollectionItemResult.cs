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
    public sealed class GetExternalDbSystemConnectorsExternalDbSystemConnectorCollectionItemResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management agent used for the external DB system connector.
        /// </summary>
        public readonly string AgentId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The error message indicating the reason for connection failure or `null` if the connection was successful.
        /// </summary>
        public readonly string ConnectionFailureMessage;
        /// <summary>
        /// The connection details required to connect to an external DB system component.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetExternalDbSystemConnectorsExternalDbSystemConnectorCollectionItemConnectionInfoResult> ConnectionInfos;
        /// <summary>
        /// The status of connectivity to the external DB system component.
        /// </summary>
        public readonly string ConnectionStatus;
        /// <summary>
        /// The type of connector.
        /// </summary>
        public readonly string ConnectorType;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// A filter to only return the resources that match the entire display name.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB system.
        /// </summary>
        public readonly string ExternalDbSystemId;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB system connector.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Additional information about the current lifecycle state.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// The current lifecycle state of the external DB system connector.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> SystemTags;
        /// <summary>
        /// The date and time the connectionStatus of the external DB system connector was last updated.
        /// </summary>
        public readonly string TimeConnectionStatusLastUpdated;
        /// <summary>
        /// The date and time the external DB system connector was created.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The date and time the external DB system connector was last updated.
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetExternalDbSystemConnectorsExternalDbSystemConnectorCollectionItemResult(
            string agentId,

            string compartmentId,

            string connectionFailureMessage,

            ImmutableArray<Outputs.GetExternalDbSystemConnectorsExternalDbSystemConnectorCollectionItemConnectionInfoResult> connectionInfos,

            string connectionStatus,

            string connectorType,

            ImmutableDictionary<string, string> definedTags,

            string displayName,

            string externalDbSystemId,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            string lifecycleDetails,

            string state,

            ImmutableDictionary<string, string> systemTags,

            string timeConnectionStatusLastUpdated,

            string timeCreated,

            string timeUpdated)
        {
            AgentId = agentId;
            CompartmentId = compartmentId;
            ConnectionFailureMessage = connectionFailureMessage;
            ConnectionInfos = connectionInfos;
            ConnectionStatus = connectionStatus;
            ConnectorType = connectorType;
            DefinedTags = definedTags;
            DisplayName = displayName;
            ExternalDbSystemId = externalDbSystemId;
            FreeformTags = freeformTags;
            Id = id;
            LifecycleDetails = lifecycleDetails;
            State = state;
            SystemTags = systemTags;
            TimeConnectionStatusLastUpdated = timeConnectionStatusLastUpdated;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
        }
    }
}
