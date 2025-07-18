// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database
{
    public static class GetExternalDatabaseConnector
    {
        /// <summary>
        /// This data source provides details about a specific External Database Connector resource in Oracle Cloud Infrastructure Database service.
        /// 
        /// Gets information about the specified external database connector.
        /// 
        /// ## Example Usage
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using System.Linq;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testExternalDatabaseConnector = Oci.Database.GetExternalDatabaseConnector.Invoke(new()
        ///     {
        ///         ExternalDatabaseConnectorId = testExternalDatabaseConnectorOciDatabaseExternalDatabaseConnector.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetExternalDatabaseConnectorResult> InvokeAsync(GetExternalDatabaseConnectorArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetExternalDatabaseConnectorResult>("oci:Database/getExternalDatabaseConnector:getExternalDatabaseConnector", args ?? new GetExternalDatabaseConnectorArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific External Database Connector resource in Oracle Cloud Infrastructure Database service.
        /// 
        /// Gets information about the specified external database connector.
        /// 
        /// ## Example Usage
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using System.Linq;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testExternalDatabaseConnector = Oci.Database.GetExternalDatabaseConnector.Invoke(new()
        ///     {
        ///         ExternalDatabaseConnectorId = testExternalDatabaseConnectorOciDatabaseExternalDatabaseConnector.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetExternalDatabaseConnectorResult> Invoke(GetExternalDatabaseConnectorInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetExternalDatabaseConnectorResult>("oci:Database/getExternalDatabaseConnector:getExternalDatabaseConnector", args ?? new GetExternalDatabaseConnectorInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific External Database Connector resource in Oracle Cloud Infrastructure Database service.
        /// 
        /// Gets information about the specified external database connector.
        /// 
        /// ## Example Usage
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using System.Linq;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testExternalDatabaseConnector = Oci.Database.GetExternalDatabaseConnector.Invoke(new()
        ///     {
        ///         ExternalDatabaseConnectorId = testExternalDatabaseConnectorOciDatabaseExternalDatabaseConnector.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetExternalDatabaseConnectorResult> Invoke(GetExternalDatabaseConnectorInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetExternalDatabaseConnectorResult>("oci:Database/getExternalDatabaseConnector:getExternalDatabaseConnector", args ?? new GetExternalDatabaseConnectorInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetExternalDatabaseConnectorArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external database connector resource (`ExternalDatabaseConnectorId`).
        /// </summary>
        [Input("externalDatabaseConnectorId", required: true)]
        public string ExternalDatabaseConnectorId { get; set; } = null!;

        public GetExternalDatabaseConnectorArgs()
        {
        }
        public static new GetExternalDatabaseConnectorArgs Empty => new GetExternalDatabaseConnectorArgs();
    }

    public sealed class GetExternalDatabaseConnectorInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external database connector resource (`ExternalDatabaseConnectorId`).
        /// </summary>
        [Input("externalDatabaseConnectorId", required: true)]
        public Input<string> ExternalDatabaseConnectorId { get; set; } = null!;

        public GetExternalDatabaseConnectorInvokeArgs()
        {
        }
        public static new GetExternalDatabaseConnectorInvokeArgs Empty => new GetExternalDatabaseConnectorInvokeArgs();
    }


    [OutputType]
    public sealed class GetExternalDatabaseConnectorResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Credentials used to connect to the database. Currently only the `DETAILS` type is supported for creating MACS connector crendentials.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetExternalDatabaseConnectorConnectionCredentialResult> ConnectionCredentials;
        /// <summary>
        /// The status of connectivity to the external database.
        /// </summary>
        public readonly string ConnectionStatus;
        /// <summary>
        /// The Oracle Database connection string.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetExternalDatabaseConnectorConnectionStringResult> ConnectionStrings;
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
        /// The user-friendly name for the [external database connector](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalDatabaseConnectorDetails). The name does not have to be unique.
        /// </summary>
        public readonly string DisplayName;
        public readonly string ExternalDatabaseConnectorId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external database resource.
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
        /// The current lifecycle state of the external database connector resource.
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
        private GetExternalDatabaseConnectorResult(
            string compartmentId,

            ImmutableArray<Outputs.GetExternalDatabaseConnectorConnectionCredentialResult> connectionCredentials,

            string connectionStatus,

            ImmutableArray<Outputs.GetExternalDatabaseConnectorConnectionStringResult> connectionStrings,

            string connectorAgentId,

            string connectorType,

            ImmutableDictionary<string, string> definedTags,

            string displayName,

            string externalDatabaseConnectorId,

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
            ExternalDatabaseConnectorId = externalDatabaseConnectorId;
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
