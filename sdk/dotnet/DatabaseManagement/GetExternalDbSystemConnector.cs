// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseManagement
{
    public static class GetExternalDbSystemConnector
    {
        /// <summary>
        /// This data source provides details about a specific External Db System Connector resource in Oracle Cloud Infrastructure Database Management service.
        /// 
        /// Gets the details for the external connector specified by `externalDbSystemConnectorId`.
        /// 
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testExternalDbSystemConnector = Oci.DatabaseManagement.GetExternalDbSystemConnector.Invoke(new()
        ///     {
        ///         ExternalDbSystemConnectorId = oci_database_management_external_db_system_connector.Test_external_db_system_connector.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetExternalDbSystemConnectorResult> InvokeAsync(GetExternalDbSystemConnectorArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetExternalDbSystemConnectorResult>("oci:DatabaseManagement/getExternalDbSystemConnector:getExternalDbSystemConnector", args ?? new GetExternalDbSystemConnectorArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific External Db System Connector resource in Oracle Cloud Infrastructure Database Management service.
        /// 
        /// Gets the details for the external connector specified by `externalDbSystemConnectorId`.
        /// 
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testExternalDbSystemConnector = Oci.DatabaseManagement.GetExternalDbSystemConnector.Invoke(new()
        ///     {
        ///         ExternalDbSystemConnectorId = oci_database_management_external_db_system_connector.Test_external_db_system_connector.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetExternalDbSystemConnectorResult> Invoke(GetExternalDbSystemConnectorInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetExternalDbSystemConnectorResult>("oci:DatabaseManagement/getExternalDbSystemConnector:getExternalDbSystemConnector", args ?? new GetExternalDbSystemConnectorInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetExternalDbSystemConnectorArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external connector.
        /// </summary>
        [Input("externalDbSystemConnectorId", required: true)]
        public string ExternalDbSystemConnectorId { get; set; } = null!;

        public GetExternalDbSystemConnectorArgs()
        {
        }
        public static new GetExternalDbSystemConnectorArgs Empty => new GetExternalDbSystemConnectorArgs();
    }

    public sealed class GetExternalDbSystemConnectorInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external connector.
        /// </summary>
        [Input("externalDbSystemConnectorId", required: true)]
        public Input<string> ExternalDbSystemConnectorId { get; set; } = null!;

        public GetExternalDbSystemConnectorInvokeArgs()
        {
        }
        public static new GetExternalDbSystemConnectorInvokeArgs Empty => new GetExternalDbSystemConnectorInvokeArgs();
    }


    [OutputType]
    public sealed class GetExternalDbSystemConnectorResult
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
        public readonly ImmutableArray<Outputs.GetExternalDbSystemConnectorConnectionInfoResult> ConnectionInfos;
        /// <summary>
        /// The status of connectivity to the external DB system component.
        /// </summary>
        public readonly string ConnectionStatus;
        /// <summary>
        /// The type of connector.
        /// </summary>
        public readonly string ConnectorType;
        /// <summary>
        /// The user-friendly name for the external connector. The name does not have to be unique.
        /// </summary>
        public readonly string DisplayName;
        public readonly string ExternalDbSystemConnectorId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB system that the connector is a part of.
        /// </summary>
        public readonly string ExternalDbSystemId;
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
        private GetExternalDbSystemConnectorResult(
            string agentId,

            string compartmentId,

            string connectionFailureMessage,

            ImmutableArray<Outputs.GetExternalDbSystemConnectorConnectionInfoResult> connectionInfos,

            string connectionStatus,

            string connectorType,

            string displayName,

            string externalDbSystemConnectorId,

            string externalDbSystemId,

            string id,

            string lifecycleDetails,

            string state,

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
            DisplayName = displayName;
            ExternalDbSystemConnectorId = externalDbSystemConnectorId;
            ExternalDbSystemId = externalDbSystemId;
            Id = id;
            LifecycleDetails = lifecycleDetails;
            State = state;
            TimeConnectionStatusLastUpdated = timeConnectionStatusLastUpdated;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
        }
    }
}