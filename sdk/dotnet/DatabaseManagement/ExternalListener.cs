// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseManagement
{
    /// <summary>
    /// This resource provides the External Listener resource in Oracle Cloud Infrastructure Database Management service.
    /// 
    /// Updates the external listener specified by `externalListenerId`.
    /// 
    /// ## Import
    /// 
    /// ExternalListeners can be imported using the `id`, e.g.
    /// 
    /// ```sh
    ///  $ pulumi import oci:DatabaseManagement/externalListener:ExternalListener test_external_listener "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:DatabaseManagement/externalListener:ExternalListener")]
    public partial class ExternalListener : global::Pulumi.CustomResource
    {
        /// <summary>
        /// The additional details of the external listener defined in `{"key": "value"}` format. Example: `{"bar-key": "value"}`
        /// </summary>
        [Output("additionalDetails")]
        public Output<ImmutableDictionary<string, object>> AdditionalDetails { get; private set; } = null!;

        /// <summary>
        /// The directory that stores tracing and logging incidents when Automatic Diagnostic Repository (ADR) is enabled.
        /// </summary>
        [Output("adrHomeDirectory")]
        public Output<string> AdrHomeDirectory { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the external database resides.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// The name of the external listener.
        /// </summary>
        [Output("componentName")]
        public Output<string> ComponentName { get; private set; } = null!;

        /// <summary>
        /// The user-friendly name for the database. The name does not have to be unique.
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// The list of protocol addresses the listener is configured to listen on.
        /// </summary>
        [Output("endpoints")]
        public Output<ImmutableArray<Outputs.ExternalListenerEndpoint>> Endpoints { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external connector.
        /// </summary>
        [Output("externalConnectorId")]
        public Output<string> ExternalConnectorId { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB home.
        /// </summary>
        [Output("externalDbHomeId")]
        public Output<string> ExternalDbHomeId { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB node.
        /// </summary>
        [Output("externalDbNodeId")]
        public Output<string> ExternalDbNodeId { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB system that the listener is a part of.
        /// </summary>
        [Output("externalDbSystemId")]
        public Output<string> ExternalDbSystemId { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external listener.
        /// </summary>
        [Output("externalListenerId")]
        public Output<string> ExternalListenerId { get; private set; } = null!;

        /// <summary>
        /// The name of the host on which the external listener is running.
        /// </summary>
        [Output("hostName")]
        public Output<string> HostName { get; private set; } = null!;

        /// <summary>
        /// Additional information about the current lifecycle state.
        /// </summary>
        [Output("lifecycleDetails")]
        public Output<string> LifecycleDetails { get; private set; } = null!;

        /// <summary>
        /// The listener alias.
        /// </summary>
        [Output("listenerAlias")]
        public Output<string> ListenerAlias { get; private set; } = null!;

        /// <summary>
        /// The location of the listener configuration file listener.ora.
        /// </summary>
        [Output("listenerOraLocation")]
        public Output<string> ListenerOraLocation { get; private set; } = null!;

        /// <summary>
        /// The type of listener.
        /// </summary>
        [Output("listenerType")]
        public Output<string> ListenerType { get; private set; } = null!;

        /// <summary>
        /// The destination directory of the listener log file.
        /// </summary>
        [Output("logDirectory")]
        public Output<string> LogDirectory { get; private set; } = null!;

        /// <summary>
        /// The Oracle home location of the listener.
        /// </summary>
        [Output("oracleHome")]
        public Output<string> OracleHome { get; private set; } = null!;

        /// <summary>
        /// The list of ASMs that are serviced by the listener.
        /// </summary>
        [Output("servicedAsms")]
        public Output<ImmutableArray<Outputs.ExternalListenerServicedAsm>> ServicedAsms { get; private set; } = null!;

        /// <summary>
        /// The list of databases that are serviced by the listener.
        /// </summary>
        [Output("servicedDatabases")]
        public Output<ImmutableArray<Outputs.ExternalListenerServicedDatabase>> ServicedDatabases { get; private set; } = null!;

        /// <summary>
        /// The current lifecycle state of the external listener.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// The date and time the external listener was created.
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// The date and time the external listener was last updated.
        /// </summary>
        [Output("timeUpdated")]
        public Output<string> TimeUpdated { get; private set; } = null!;

        /// <summary>
        /// The destination directory of the listener trace file.
        /// </summary>
        [Output("traceDirectory")]
        public Output<string> TraceDirectory { get; private set; } = null!;

        /// <summary>
        /// The listener version.
        /// </summary>
        [Output("version")]
        public Output<string> Version { get; private set; } = null!;


        /// <summary>
        /// Create a ExternalListener resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public ExternalListener(string name, ExternalListenerArgs args, CustomResourceOptions? options = null)
            : base("oci:DatabaseManagement/externalListener:ExternalListener", name, args ?? new ExternalListenerArgs(), MakeResourceOptions(options, ""))
        {
        }

        private ExternalListener(string name, Input<string> id, ExternalListenerState? state = null, CustomResourceOptions? options = null)
            : base("oci:DatabaseManagement/externalListener:ExternalListener", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing ExternalListener resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static ExternalListener Get(string name, Input<string> id, ExternalListenerState? state = null, CustomResourceOptions? options = null)
        {
            return new ExternalListener(name, id, state, options);
        }
    }

    public sealed class ExternalListenerArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external connector.
        /// </summary>
        [Input("externalConnectorId")]
        public Input<string>? ExternalConnectorId { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external listener.
        /// </summary>
        [Input("externalListenerId", required: true)]
        public Input<string> ExternalListenerId { get; set; } = null!;

        public ExternalListenerArgs()
        {
        }
        public static new ExternalListenerArgs Empty => new ExternalListenerArgs();
    }

    public sealed class ExternalListenerState : global::Pulumi.ResourceArgs
    {
        [Input("additionalDetails")]
        private InputMap<object>? _additionalDetails;

        /// <summary>
        /// The additional details of the external listener defined in `{"key": "value"}` format. Example: `{"bar-key": "value"}`
        /// </summary>
        public InputMap<object> AdditionalDetails
        {
            get => _additionalDetails ?? (_additionalDetails = new InputMap<object>());
            set => _additionalDetails = value;
        }

        /// <summary>
        /// The directory that stores tracing and logging incidents when Automatic Diagnostic Repository (ADR) is enabled.
        /// </summary>
        [Input("adrHomeDirectory")]
        public Input<string>? AdrHomeDirectory { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the external database resides.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        /// <summary>
        /// The name of the external listener.
        /// </summary>
        [Input("componentName")]
        public Input<string>? ComponentName { get; set; }

        /// <summary>
        /// The user-friendly name for the database. The name does not have to be unique.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("endpoints")]
        private InputList<Inputs.ExternalListenerEndpointGetArgs>? _endpoints;

        /// <summary>
        /// The list of protocol addresses the listener is configured to listen on.
        /// </summary>
        public InputList<Inputs.ExternalListenerEndpointGetArgs> Endpoints
        {
            get => _endpoints ?? (_endpoints = new InputList<Inputs.ExternalListenerEndpointGetArgs>());
            set => _endpoints = value;
        }

        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external connector.
        /// </summary>
        [Input("externalConnectorId")]
        public Input<string>? ExternalConnectorId { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB home.
        /// </summary>
        [Input("externalDbHomeId")]
        public Input<string>? ExternalDbHomeId { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB node.
        /// </summary>
        [Input("externalDbNodeId")]
        public Input<string>? ExternalDbNodeId { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB system that the listener is a part of.
        /// </summary>
        [Input("externalDbSystemId")]
        public Input<string>? ExternalDbSystemId { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external listener.
        /// </summary>
        [Input("externalListenerId")]
        public Input<string>? ExternalListenerId { get; set; }

        /// <summary>
        /// The name of the host on which the external listener is running.
        /// </summary>
        [Input("hostName")]
        public Input<string>? HostName { get; set; }

        /// <summary>
        /// Additional information about the current lifecycle state.
        /// </summary>
        [Input("lifecycleDetails")]
        public Input<string>? LifecycleDetails { get; set; }

        /// <summary>
        /// The listener alias.
        /// </summary>
        [Input("listenerAlias")]
        public Input<string>? ListenerAlias { get; set; }

        /// <summary>
        /// The location of the listener configuration file listener.ora.
        /// </summary>
        [Input("listenerOraLocation")]
        public Input<string>? ListenerOraLocation { get; set; }

        /// <summary>
        /// The type of listener.
        /// </summary>
        [Input("listenerType")]
        public Input<string>? ListenerType { get; set; }

        /// <summary>
        /// The destination directory of the listener log file.
        /// </summary>
        [Input("logDirectory")]
        public Input<string>? LogDirectory { get; set; }

        /// <summary>
        /// The Oracle home location of the listener.
        /// </summary>
        [Input("oracleHome")]
        public Input<string>? OracleHome { get; set; }

        [Input("servicedAsms")]
        private InputList<Inputs.ExternalListenerServicedAsmGetArgs>? _servicedAsms;

        /// <summary>
        /// The list of ASMs that are serviced by the listener.
        /// </summary>
        public InputList<Inputs.ExternalListenerServicedAsmGetArgs> ServicedAsms
        {
            get => _servicedAsms ?? (_servicedAsms = new InputList<Inputs.ExternalListenerServicedAsmGetArgs>());
            set => _servicedAsms = value;
        }

        [Input("servicedDatabases")]
        private InputList<Inputs.ExternalListenerServicedDatabaseGetArgs>? _servicedDatabases;

        /// <summary>
        /// The list of databases that are serviced by the listener.
        /// </summary>
        public InputList<Inputs.ExternalListenerServicedDatabaseGetArgs> ServicedDatabases
        {
            get => _servicedDatabases ?? (_servicedDatabases = new InputList<Inputs.ExternalListenerServicedDatabaseGetArgs>());
            set => _servicedDatabases = value;
        }

        /// <summary>
        /// The current lifecycle state of the external listener.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        /// <summary>
        /// The date and time the external listener was created.
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// The date and time the external listener was last updated.
        /// </summary>
        [Input("timeUpdated")]
        public Input<string>? TimeUpdated { get; set; }

        /// <summary>
        /// The destination directory of the listener trace file.
        /// </summary>
        [Input("traceDirectory")]
        public Input<string>? TraceDirectory { get; set; }

        /// <summary>
        /// The listener version.
        /// </summary>
        [Input("version")]
        public Input<string>? Version { get; set; }

        public ExternalListenerState()
        {
        }
        public static new ExternalListenerState Empty => new ExternalListenerState();
    }
}