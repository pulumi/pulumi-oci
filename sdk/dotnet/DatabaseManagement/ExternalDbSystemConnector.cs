// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseManagement
{
    /// <summary>
    /// This resource provides the External Db System Connector resource in Oracle Cloud Infrastructure Database Management service.
    /// 
    /// Creates a new external connector.
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
    ///     var testExternalDbSystemConnector = new Oci.DatabaseManagement.ExternalDbSystemConnector("test_external_db_system_connector", new()
    ///     {
    ///         ConnectorType = externalDbSystemConnectorConnectorType,
    ///         ExternalDbSystemId = testExternalDbSystem.Id,
    ///         DisplayName = externalDbSystemConnectorDisplayName,
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// ExternalDbSystemConnectors can be imported using the `id`, e.g.
    /// 
    /// ```sh
    /// $ pulumi import oci:DatabaseManagement/externalDbSystemConnector:ExternalDbSystemConnector test_external_db_system_connector "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:DatabaseManagement/externalDbSystemConnector:ExternalDbSystemConnector")]
    public partial class ExternalDbSystemConnector : global::Pulumi.CustomResource
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management agent used for the external DB system connector.
        /// </summary>
        [Output("agentId")]
        public Output<string> AgentId { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// The error message indicating the reason for connection failure or `null` if the connection was successful.
        /// </summary>
        [Output("connectionFailureMessage")]
        public Output<string> ConnectionFailureMessage { get; private set; } = null!;

        /// <summary>
        /// The connection details required to connect to an external DB system component.
        /// </summary>
        [Output("connectionInfos")]
        public Output<ImmutableArray<Outputs.ExternalDbSystemConnectorConnectionInfo>> ConnectionInfos { get; private set; } = null!;

        /// <summary>
        /// The status of connectivity to the external DB system component.
        /// </summary>
        [Output("connectionStatus")]
        public Output<string> ConnectionStatus { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The type of connector.
        /// </summary>
        [Output("connectorType")]
        public Output<string> ConnectorType { get; private set; } = null!;

        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, string>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// The user-friendly name for the external connector. The name does not have to be unique.
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB system.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Output("externalDbSystemId")]
        public Output<string> ExternalDbSystemId { get; private set; } = null!;

        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, string>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// Additional information about the current lifecycle state.
        /// </summary>
        [Output("lifecycleDetails")]
        public Output<string> LifecycleDetails { get; private set; } = null!;

        /// <summary>
        /// The current lifecycle state of the external DB system connector.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        [Output("systemTags")]
        public Output<ImmutableDictionary<string, string>> SystemTags { get; private set; } = null!;

        /// <summary>
        /// The date and time the connectionStatus of the external DB system connector was last updated.
        /// </summary>
        [Output("timeConnectionStatusLastUpdated")]
        public Output<string> TimeConnectionStatusLastUpdated { get; private set; } = null!;

        /// <summary>
        /// The date and time the external DB system connector was created.
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// The date and time the external DB system connector was last updated.
        /// </summary>
        [Output("timeUpdated")]
        public Output<string> TimeUpdated { get; private set; } = null!;


        /// <summary>
        /// Create a ExternalDbSystemConnector resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public ExternalDbSystemConnector(string name, ExternalDbSystemConnectorArgs args, CustomResourceOptions? options = null)
            : base("oci:DatabaseManagement/externalDbSystemConnector:ExternalDbSystemConnector", name, args ?? new ExternalDbSystemConnectorArgs(), MakeResourceOptions(options, ""))
        {
        }

        private ExternalDbSystemConnector(string name, Input<string> id, ExternalDbSystemConnectorState? state = null, CustomResourceOptions? options = null)
            : base("oci:DatabaseManagement/externalDbSystemConnector:ExternalDbSystemConnector", name, state, MakeResourceOptions(options, id))
        {
        }

        private static CustomResourceOptions MakeResourceOptions(CustomResourceOptions? options, Input<string>? id)
        {
            var defaultOptions = new CustomResourceOptions
            {
                Version = Utilities.Version,
            };
            var merged = CustomResourceOptions.Merge(defaultOptions, options);
            // Override the ID if one was specified for consistency with other language SDKs.
            merged.Id = id ?? merged.Id;
            return merged;
        }
        /// <summary>
        /// Get an existing ExternalDbSystemConnector resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static ExternalDbSystemConnector Get(string name, Input<string> id, ExternalDbSystemConnectorState? state = null, CustomResourceOptions? options = null)
        {
            return new ExternalDbSystemConnector(name, id, state, options);
        }
    }

    public sealed class ExternalDbSystemConnectorArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management agent used for the external DB system connector.
        /// </summary>
        [Input("agentId")]
        public Input<string>? AgentId { get; set; }

        [Input("connectionInfos")]
        private InputList<Inputs.ExternalDbSystemConnectorConnectionInfoArgs>? _connectionInfos;

        /// <summary>
        /// The connection details required to connect to an external DB system component.
        /// </summary>
        public InputList<Inputs.ExternalDbSystemConnectorConnectionInfoArgs> ConnectionInfos
        {
            get => _connectionInfos ?? (_connectionInfos = new InputList<Inputs.ExternalDbSystemConnectorConnectionInfoArgs>());
            set => _connectionInfos = value;
        }

        /// <summary>
        /// (Updatable) The type of connector.
        /// </summary>
        [Input("connectorType", required: true)]
        public Input<string> ConnectorType { get; set; } = null!;

        [Input("definedTags")]
        private InputMap<string>? _definedTags;

        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public InputMap<string> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<string>());
            set => _definedTags = value;
        }

        /// <summary>
        /// The user-friendly name for the external connector. The name does not have to be unique.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB system.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("externalDbSystemId", required: true)]
        public Input<string> ExternalDbSystemId { get; set; } = null!;

        [Input("freeformTags")]
        private InputMap<string>? _freeformTags;

        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        public InputMap<string> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<string>());
            set => _freeformTags = value;
        }

        public ExternalDbSystemConnectorArgs()
        {
        }
        public static new ExternalDbSystemConnectorArgs Empty => new ExternalDbSystemConnectorArgs();
    }

    public sealed class ExternalDbSystemConnectorState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management agent used for the external DB system connector.
        /// </summary>
        [Input("agentId")]
        public Input<string>? AgentId { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        /// <summary>
        /// The error message indicating the reason for connection failure or `null` if the connection was successful.
        /// </summary>
        [Input("connectionFailureMessage")]
        public Input<string>? ConnectionFailureMessage { get; set; }

        [Input("connectionInfos")]
        private InputList<Inputs.ExternalDbSystemConnectorConnectionInfoGetArgs>? _connectionInfos;

        /// <summary>
        /// The connection details required to connect to an external DB system component.
        /// </summary>
        public InputList<Inputs.ExternalDbSystemConnectorConnectionInfoGetArgs> ConnectionInfos
        {
            get => _connectionInfos ?? (_connectionInfos = new InputList<Inputs.ExternalDbSystemConnectorConnectionInfoGetArgs>());
            set => _connectionInfos = value;
        }

        /// <summary>
        /// The status of connectivity to the external DB system component.
        /// </summary>
        [Input("connectionStatus")]
        public Input<string>? ConnectionStatus { get; set; }

        /// <summary>
        /// (Updatable) The type of connector.
        /// </summary>
        [Input("connectorType")]
        public Input<string>? ConnectorType { get; set; }

        [Input("definedTags")]
        private InputMap<string>? _definedTags;

        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public InputMap<string> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<string>());
            set => _definedTags = value;
        }

        /// <summary>
        /// The user-friendly name for the external connector. The name does not have to be unique.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB system.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("externalDbSystemId")]
        public Input<string>? ExternalDbSystemId { get; set; }

        [Input("freeformTags")]
        private InputMap<string>? _freeformTags;

        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        public InputMap<string> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<string>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// Additional information about the current lifecycle state.
        /// </summary>
        [Input("lifecycleDetails")]
        public Input<string>? LifecycleDetails { get; set; }

        /// <summary>
        /// The current lifecycle state of the external DB system connector.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        [Input("systemTags")]
        private InputMap<string>? _systemTags;

        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public InputMap<string> SystemTags
        {
            get => _systemTags ?? (_systemTags = new InputMap<string>());
            set => _systemTags = value;
        }

        /// <summary>
        /// The date and time the connectionStatus of the external DB system connector was last updated.
        /// </summary>
        [Input("timeConnectionStatusLastUpdated")]
        public Input<string>? TimeConnectionStatusLastUpdated { get; set; }

        /// <summary>
        /// The date and time the external DB system connector was created.
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// The date and time the external DB system connector was last updated.
        /// </summary>
        [Input("timeUpdated")]
        public Input<string>? TimeUpdated { get; set; }

        public ExternalDbSystemConnectorState()
        {
        }
        public static new ExternalDbSystemConnectorState Empty => new ExternalDbSystemConnectorState();
    }
}
