// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseTools
{
    public static class GetDatabaseToolsConnections
    {
        /// <summary>
        /// This data source provides the list of Database Tools Connections in Oracle Cloud Infrastructure Database Tools service.
        /// 
        /// Returns a list of Database Tools connections.
        /// 
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
        ///     var testDatabaseToolsConnections = Oci.DatabaseTools.GetDatabaseToolsConnections.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         DisplayName = databaseToolsConnectionDisplayName,
        ///         RelatedResourceIdentifier = databaseToolsConnectionRelatedResourceIdentifier,
        ///         RuntimeSupports = databaseToolsConnectionRuntimeSupport,
        ///         State = databaseToolsConnectionState,
        ///         Types = databaseToolsConnectionType,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetDatabaseToolsConnectionsResult> InvokeAsync(GetDatabaseToolsConnectionsArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetDatabaseToolsConnectionsResult>("oci:DatabaseTools/getDatabaseToolsConnections:getDatabaseToolsConnections", args ?? new GetDatabaseToolsConnectionsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Database Tools Connections in Oracle Cloud Infrastructure Database Tools service.
        /// 
        /// Returns a list of Database Tools connections.
        /// 
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
        ///     var testDatabaseToolsConnections = Oci.DatabaseTools.GetDatabaseToolsConnections.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         DisplayName = databaseToolsConnectionDisplayName,
        ///         RelatedResourceIdentifier = databaseToolsConnectionRelatedResourceIdentifier,
        ///         RuntimeSupports = databaseToolsConnectionRuntimeSupport,
        ///         State = databaseToolsConnectionState,
        ///         Types = databaseToolsConnectionType,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetDatabaseToolsConnectionsResult> Invoke(GetDatabaseToolsConnectionsInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetDatabaseToolsConnectionsResult>("oci:DatabaseTools/getDatabaseToolsConnections:getDatabaseToolsConnections", args ?? new GetDatabaseToolsConnectionsInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Database Tools Connections in Oracle Cloud Infrastructure Database Tools service.
        /// 
        /// Returns a list of Database Tools connections.
        /// 
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
        ///     var testDatabaseToolsConnections = Oci.DatabaseTools.GetDatabaseToolsConnections.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         DisplayName = databaseToolsConnectionDisplayName,
        ///         RelatedResourceIdentifier = databaseToolsConnectionRelatedResourceIdentifier,
        ///         RuntimeSupports = databaseToolsConnectionRuntimeSupport,
        ///         State = databaseToolsConnectionState,
        ///         Types = databaseToolsConnectionType,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetDatabaseToolsConnectionsResult> Invoke(GetDatabaseToolsConnectionsInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetDatabaseToolsConnectionsResult>("oci:DatabaseTools/getDatabaseToolsConnections:getDatabaseToolsConnections", args ?? new GetDatabaseToolsConnectionsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetDatabaseToolsConnectionsArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The ID of the compartment in which to list resources.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// A filter to return only resources that match the entire specified display name.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetDatabaseToolsConnectionsFilterArgs>? _filters;
        public List<Inputs.GetDatabaseToolsConnectionsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetDatabaseToolsConnectionsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only resources associated to the related resource identifier OCID passed in the query string.
        /// </summary>
        [Input("relatedResourceIdentifier")]
        public string? RelatedResourceIdentifier { get; set; }

        [Input("runtimeSupports")]
        private List<string>? _runtimeSupports;

        /// <summary>
        /// A filter to return only resources with one of the specified runtimeSupport values.
        /// </summary>
        public List<string> RuntimeSupports
        {
            get => _runtimeSupports ?? (_runtimeSupports = new List<string>());
            set => _runtimeSupports = value;
        }

        /// <summary>
        /// A filter to return only resources their `lifecycleState` matches the specified `lifecycleState`.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        [Input("types")]
        private List<string>? _types;

        /// <summary>
        /// A filter to return only resources their type matches the specified type.
        /// </summary>
        public List<string> Types
        {
            get => _types ?? (_types = new List<string>());
            set => _types = value;
        }

        public GetDatabaseToolsConnectionsArgs()
        {
        }
        public static new GetDatabaseToolsConnectionsArgs Empty => new GetDatabaseToolsConnectionsArgs();
    }

    public sealed class GetDatabaseToolsConnectionsInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The ID of the compartment in which to list resources.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// A filter to return only resources that match the entire specified display name.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetDatabaseToolsConnectionsFilterInputArgs>? _filters;
        public InputList<Inputs.GetDatabaseToolsConnectionsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetDatabaseToolsConnectionsFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only resources associated to the related resource identifier OCID passed in the query string.
        /// </summary>
        [Input("relatedResourceIdentifier")]
        public Input<string>? RelatedResourceIdentifier { get; set; }

        [Input("runtimeSupports")]
        private InputList<string>? _runtimeSupports;

        /// <summary>
        /// A filter to return only resources with one of the specified runtimeSupport values.
        /// </summary>
        public InputList<string> RuntimeSupports
        {
            get => _runtimeSupports ?? (_runtimeSupports = new InputList<string>());
            set => _runtimeSupports = value;
        }

        /// <summary>
        /// A filter to return only resources their `lifecycleState` matches the specified `lifecycleState`.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        [Input("types")]
        private InputList<string>? _types;

        /// <summary>
        /// A filter to return only resources their type matches the specified type.
        /// </summary>
        public InputList<string> Types
        {
            get => _types ?? (_types = new InputList<string>());
            set => _types = value;
        }

        public GetDatabaseToolsConnectionsInvokeArgs()
        {
        }
        public static new GetDatabaseToolsConnectionsInvokeArgs Empty => new GetDatabaseToolsConnectionsInvokeArgs();
    }


    [OutputType]
    public sealed class GetDatabaseToolsConnectionsResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the Database Tools connection.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The list of database_tools_connection_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDatabaseToolsConnectionsDatabaseToolsConnectionCollectionResult> DatabaseToolsConnectionCollections;
        /// <summary>
        /// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetDatabaseToolsConnectionsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly string? RelatedResourceIdentifier;
        /// <summary>
        /// Specifies whether this connection is supported by the Database Tools Runtime.
        /// </summary>
        public readonly ImmutableArray<string> RuntimeSupports;
        /// <summary>
        /// The current state of the Database Tools connection.
        /// </summary>
        public readonly string? State;
        /// <summary>
        /// The Database Tools connection type.
        /// </summary>
        public readonly ImmutableArray<string> Types;

        [OutputConstructor]
        private GetDatabaseToolsConnectionsResult(
            string compartmentId,

            ImmutableArray<Outputs.GetDatabaseToolsConnectionsDatabaseToolsConnectionCollectionResult> databaseToolsConnectionCollections,

            string? displayName,

            ImmutableArray<Outputs.GetDatabaseToolsConnectionsFilterResult> filters,

            string id,

            string? relatedResourceIdentifier,

            ImmutableArray<string> runtimeSupports,

            string? state,

            ImmutableArray<string> types)
        {
            CompartmentId = compartmentId;
            DatabaseToolsConnectionCollections = databaseToolsConnectionCollections;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            RelatedResourceIdentifier = relatedResourceIdentifier;
            RuntimeSupports = runtimeSupports;
            State = state;
            Types = types;
        }
    }
}
