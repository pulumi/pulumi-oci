// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseTools
{
    /// <summary>
    /// This resource provides the Database Tools Connection resource in Oracle Cloud Infrastructure Database Tools service.
    /// 
    /// Creates a new Database Tools connection.
    /// 
    /// ## Import
    /// 
    /// DatabaseToolsConnections can be imported using the `id`, e.g.
    /// 
    /// ```sh
    /// $ pulumi import oci:DatabaseTools/databaseToolsConnection:DatabaseToolsConnection test_database_tools_connection "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:DatabaseTools/databaseToolsConnection:DatabaseToolsConnection")]
    public partial class DatabaseToolsConnection : global::Pulumi.CustomResource
    {
        /// <summary>
        /// (Updatable) The advanced connection properties key-value pair (e.g., `oracle.net.ssl_server_dn_match`).
        /// </summary>
        [Output("advancedProperties")]
        public Output<ImmutableDictionary<string, string>> AdvancedProperties { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the Database Tools connection.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The connect descriptor or Easy Connect Naming method use to connect to the database.
        /// </summary>
        [Output("connectionString")]
        public Output<string> ConnectionString { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, string>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, string>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Oracle wallet or Java Keystores containing trusted certificates for authenticating the server's public certificate and the client private key and associated certificates required for client authentication.
        /// </summary>
        [Output("keyStores")]
        public Output<ImmutableArray<Outputs.DatabaseToolsConnectionKeyStore>> KeyStores { get; private set; } = null!;

        /// <summary>
        /// A message describing the current state in more detail. For example, this message can be used to provide actionable information for a resource in the Failed state.
        /// </summary>
        [Output("lifecycleDetails")]
        public Output<string> LifecycleDetails { get; private set; } = null!;

        /// <summary>
        /// Locks associated with this resource.
        /// </summary>
        [Output("locks")]
        public Output<ImmutableArray<Outputs.DatabaseToolsConnectionLock>> Locks { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Database Tools private endpoint used to access the database in the customer VCN.
        /// </summary>
        [Output("privateEndpointId")]
        public Output<string> PrivateEndpointId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The proxy client information.
        /// </summary>
        [Output("proxyClient")]
        public Output<Outputs.DatabaseToolsConnectionProxyClient> ProxyClient { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The related resource
        /// </summary>
        [Output("relatedResource")]
        public Output<Outputs.DatabaseToolsConnectionRelatedResource> RelatedResource { get; private set; } = null!;

        /// <summary>
        /// Specifies whether this connection is supported by the Database Tools Runtime.
        /// </summary>
        [Output("runtimeSupport")]
        public Output<string> RuntimeSupport { get; private set; } = null!;

        /// <summary>
        /// The current state of the Database Tools connection.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        [Output("systemTags")]
        public Output<ImmutableDictionary<string, string>> SystemTags { get; private set; } = null!;

        /// <summary>
        /// The time the Database Tools connection was created. An RFC3339 formatted datetime string.
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// The time the DatabaseToolsConnection was updated. An RFC3339 formatted datetime string.
        /// </summary>
        [Output("timeUpdated")]
        public Output<string> TimeUpdated { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The DatabaseToolsConnection type.
        /// </summary>
        [Output("type")]
        public Output<string> Type { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The JDBC URL used to connect to the Generic JDBC database system.
        /// </summary>
        [Output("url")]
        public Output<string> Url { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The database user name.
        /// </summary>
        [Output("userName")]
        public Output<string> UserName { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The user password.
        /// </summary>
        [Output("userPassword")]
        public Output<Outputs.DatabaseToolsConnectionUserPassword> UserPassword { get; private set; } = null!;


        /// <summary>
        /// Create a DatabaseToolsConnection resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public DatabaseToolsConnection(string name, DatabaseToolsConnectionArgs args, CustomResourceOptions? options = null)
            : base("oci:DatabaseTools/databaseToolsConnection:DatabaseToolsConnection", name, args ?? new DatabaseToolsConnectionArgs(), MakeResourceOptions(options, ""))
        {
        }

        private DatabaseToolsConnection(string name, Input<string> id, DatabaseToolsConnectionState? state = null, CustomResourceOptions? options = null)
            : base("oci:DatabaseTools/databaseToolsConnection:DatabaseToolsConnection", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing DatabaseToolsConnection resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static DatabaseToolsConnection Get(string name, Input<string> id, DatabaseToolsConnectionState? state = null, CustomResourceOptions? options = null)
        {
            return new DatabaseToolsConnection(name, id, state, options);
        }
    }

    public sealed class DatabaseToolsConnectionArgs : global::Pulumi.ResourceArgs
    {
        [Input("advancedProperties")]
        private InputMap<string>? _advancedProperties;

        /// <summary>
        /// (Updatable) The advanced connection properties key-value pair (e.g., `oracle.net.ssl_server_dn_match`).
        /// </summary>
        public InputMap<string> AdvancedProperties
        {
            get => _advancedProperties ?? (_advancedProperties = new InputMap<string>());
            set => _advancedProperties = value;
        }

        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the Database Tools connection.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// (Updatable) The connect descriptor or Easy Connect Naming method use to connect to the database.
        /// </summary>
        [Input("connectionString")]
        public Input<string>? ConnectionString { get; set; }

        [Input("definedTags")]
        private InputMap<string>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public InputMap<string> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<string>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        [Input("displayName", required: true)]
        public Input<string> DisplayName { get; set; } = null!;

        [Input("freeformTags")]
        private InputMap<string>? _freeformTags;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public InputMap<string> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<string>());
            set => _freeformTags = value;
        }

        [Input("keyStores")]
        private InputList<Inputs.DatabaseToolsConnectionKeyStoreArgs>? _keyStores;

        /// <summary>
        /// (Updatable) Oracle wallet or Java Keystores containing trusted certificates for authenticating the server's public certificate and the client private key and associated certificates required for client authentication.
        /// </summary>
        public InputList<Inputs.DatabaseToolsConnectionKeyStoreArgs> KeyStores
        {
            get => _keyStores ?? (_keyStores = new InputList<Inputs.DatabaseToolsConnectionKeyStoreArgs>());
            set => _keyStores = value;
        }

        [Input("locks")]
        private InputList<Inputs.DatabaseToolsConnectionLockArgs>? _locks;

        /// <summary>
        /// Locks associated with this resource.
        /// </summary>
        public InputList<Inputs.DatabaseToolsConnectionLockArgs> Locks
        {
            get => _locks ?? (_locks = new InputList<Inputs.DatabaseToolsConnectionLockArgs>());
            set => _locks = value;
        }

        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Database Tools private endpoint used to access the database in the customer VCN.
        /// </summary>
        [Input("privateEndpointId")]
        public Input<string>? PrivateEndpointId { get; set; }

        /// <summary>
        /// (Updatable) The proxy client information.
        /// </summary>
        [Input("proxyClient")]
        public Input<Inputs.DatabaseToolsConnectionProxyClientArgs>? ProxyClient { get; set; }

        /// <summary>
        /// (Updatable) The related resource
        /// </summary>
        [Input("relatedResource")]
        public Input<Inputs.DatabaseToolsConnectionRelatedResourceArgs>? RelatedResource { get; set; }

        /// <summary>
        /// Specifies whether this connection is supported by the Database Tools Runtime.
        /// </summary>
        [Input("runtimeSupport")]
        public Input<string>? RuntimeSupport { get; set; }

        /// <summary>
        /// (Updatable) The DatabaseToolsConnection type.
        /// </summary>
        [Input("type", required: true)]
        public Input<string> Type { get; set; } = null!;

        /// <summary>
        /// (Updatable) The JDBC URL used to connect to the Generic JDBC database system.
        /// </summary>
        [Input("url")]
        public Input<string>? Url { get; set; }

        /// <summary>
        /// (Updatable) The database user name.
        /// </summary>
        [Input("userName", required: true)]
        public Input<string> UserName { get; set; } = null!;

        /// <summary>
        /// (Updatable) The user password.
        /// </summary>
        [Input("userPassword", required: true)]
        public Input<Inputs.DatabaseToolsConnectionUserPasswordArgs> UserPassword { get; set; } = null!;

        public DatabaseToolsConnectionArgs()
        {
        }
        public static new DatabaseToolsConnectionArgs Empty => new DatabaseToolsConnectionArgs();
    }

    public sealed class DatabaseToolsConnectionState : global::Pulumi.ResourceArgs
    {
        [Input("advancedProperties")]
        private InputMap<string>? _advancedProperties;

        /// <summary>
        /// (Updatable) The advanced connection properties key-value pair (e.g., `oracle.net.ssl_server_dn_match`).
        /// </summary>
        public InputMap<string> AdvancedProperties
        {
            get => _advancedProperties ?? (_advancedProperties = new InputMap<string>());
            set => _advancedProperties = value;
        }

        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the Database Tools connection.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        /// <summary>
        /// (Updatable) The connect descriptor or Easy Connect Naming method use to connect to the database.
        /// </summary>
        [Input("connectionString")]
        public Input<string>? ConnectionString { get; set; }

        [Input("definedTags")]
        private InputMap<string>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public InputMap<string> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<string>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("freeformTags")]
        private InputMap<string>? _freeformTags;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public InputMap<string> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<string>());
            set => _freeformTags = value;
        }

        [Input("keyStores")]
        private InputList<Inputs.DatabaseToolsConnectionKeyStoreGetArgs>? _keyStores;

        /// <summary>
        /// (Updatable) Oracle wallet or Java Keystores containing trusted certificates for authenticating the server's public certificate and the client private key and associated certificates required for client authentication.
        /// </summary>
        public InputList<Inputs.DatabaseToolsConnectionKeyStoreGetArgs> KeyStores
        {
            get => _keyStores ?? (_keyStores = new InputList<Inputs.DatabaseToolsConnectionKeyStoreGetArgs>());
            set => _keyStores = value;
        }

        /// <summary>
        /// A message describing the current state in more detail. For example, this message can be used to provide actionable information for a resource in the Failed state.
        /// </summary>
        [Input("lifecycleDetails")]
        public Input<string>? LifecycleDetails { get; set; }

        [Input("locks")]
        private InputList<Inputs.DatabaseToolsConnectionLockGetArgs>? _locks;

        /// <summary>
        /// Locks associated with this resource.
        /// </summary>
        public InputList<Inputs.DatabaseToolsConnectionLockGetArgs> Locks
        {
            get => _locks ?? (_locks = new InputList<Inputs.DatabaseToolsConnectionLockGetArgs>());
            set => _locks = value;
        }

        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Database Tools private endpoint used to access the database in the customer VCN.
        /// </summary>
        [Input("privateEndpointId")]
        public Input<string>? PrivateEndpointId { get; set; }

        /// <summary>
        /// (Updatable) The proxy client information.
        /// </summary>
        [Input("proxyClient")]
        public Input<Inputs.DatabaseToolsConnectionProxyClientGetArgs>? ProxyClient { get; set; }

        /// <summary>
        /// (Updatable) The related resource
        /// </summary>
        [Input("relatedResource")]
        public Input<Inputs.DatabaseToolsConnectionRelatedResourceGetArgs>? RelatedResource { get; set; }

        /// <summary>
        /// Specifies whether this connection is supported by the Database Tools Runtime.
        /// </summary>
        [Input("runtimeSupport")]
        public Input<string>? RuntimeSupport { get; set; }

        /// <summary>
        /// The current state of the Database Tools connection.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        [Input("systemTags")]
        private InputMap<string>? _systemTags;

        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public InputMap<string> SystemTags
        {
            get => _systemTags ?? (_systemTags = new InputMap<string>());
            set => _systemTags = value;
        }

        /// <summary>
        /// The time the Database Tools connection was created. An RFC3339 formatted datetime string.
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// The time the DatabaseToolsConnection was updated. An RFC3339 formatted datetime string.
        /// </summary>
        [Input("timeUpdated")]
        public Input<string>? TimeUpdated { get; set; }

        /// <summary>
        /// (Updatable) The DatabaseToolsConnection type.
        /// </summary>
        [Input("type")]
        public Input<string>? Type { get; set; }

        /// <summary>
        /// (Updatable) The JDBC URL used to connect to the Generic JDBC database system.
        /// </summary>
        [Input("url")]
        public Input<string>? Url { get; set; }

        /// <summary>
        /// (Updatable) The database user name.
        /// </summary>
        [Input("userName")]
        public Input<string>? UserName { get; set; }

        /// <summary>
        /// (Updatable) The user password.
        /// </summary>
        [Input("userPassword")]
        public Input<Inputs.DatabaseToolsConnectionUserPasswordGetArgs>? UserPassword { get; set; }

        public DatabaseToolsConnectionState()
        {
        }
        public static new DatabaseToolsConnectionState Empty => new DatabaseToolsConnectionState();
    }
}
