// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataConnectivity
{
    public static class GetRegistryConnections
    {
        /// <summary>
        /// This data source provides the list of Registry Connections in Oracle Cloud Infrastructure Data Connectivity service.
        /// 
        /// Retrieves a list of all connections.
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// class MyStack : Stack
        /// {
        ///     public MyStack()
        ///     {
        ///         var testRegistryConnections = Output.Create(Oci.DataConnectivity.GetRegistryConnections.InvokeAsync(new Oci.DataConnectivity.GetRegistryConnectionsArgs
        ///         {
        ///             DataAssetKey = @var.Registry_connection_data_asset_key,
        ///             RegistryId = oci_data_connectivity_registry.Test_registry.Id,
        ///             FavoritesQueryParam = @var.Registry_connection_favorites_query_param,
        ///             Fields = @var.Registry_connection_fields,
        ///             Name = @var.Registry_connection_name,
        ///             Type = @var.Registry_connection_type,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetRegistryConnectionsResult> InvokeAsync(GetRegistryConnectionsArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetRegistryConnectionsResult>("oci:DataConnectivity/getRegistryConnections:getRegistryConnections", args ?? new GetRegistryConnectionsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Registry Connections in Oracle Cloud Infrastructure Data Connectivity service.
        /// 
        /// Retrieves a list of all connections.
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// class MyStack : Stack
        /// {
        ///     public MyStack()
        ///     {
        ///         var testRegistryConnections = Output.Create(Oci.DataConnectivity.GetRegistryConnections.InvokeAsync(new Oci.DataConnectivity.GetRegistryConnectionsArgs
        ///         {
        ///             DataAssetKey = @var.Registry_connection_data_asset_key,
        ///             RegistryId = oci_data_connectivity_registry.Test_registry.Id,
        ///             FavoritesQueryParam = @var.Registry_connection_favorites_query_param,
        ///             Fields = @var.Registry_connection_fields,
        ///             Name = @var.Registry_connection_name,
        ///             Type = @var.Registry_connection_type,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetRegistryConnectionsResult> Invoke(GetRegistryConnectionsInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetRegistryConnectionsResult>("oci:DataConnectivity/getRegistryConnections:getRegistryConnections", args ?? new GetRegistryConnectionsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetRegistryConnectionsArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// Used to filter by the data asset key of the object.
        /// </summary>
        [Input("dataAssetKey", required: true)]
        public string DataAssetKey { get; set; } = null!;

        /// <summary>
        /// If value is FAVORITES_ONLY, then only objects marked as favorite by the requesting user will be included in result. If value is NON_FAVORITES_ONLY, then objects marked as favorites by the requesting user will be skipped. If value is ALL or if not specified, all objects, irrespective of favorites or not will be returned. Default is ALL.
        /// </summary>
        [Input("favoritesQueryParam")]
        public string? FavoritesQueryParam { get; set; }

        [Input("fields")]
        private List<string>? _fields;

        /// <summary>
        /// Specifies the fields to get for an object.
        /// </summary>
        public List<string> Fields
        {
            get => _fields ?? (_fields = new List<string>());
            set => _fields = value;
        }

        [Input("filters")]
        private List<Inputs.GetRegistryConnectionsFilterArgs>? _filters;
        public List<Inputs.GetRegistryConnectionsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetRegistryConnectionsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// Used to filter by the name of the object.
        /// </summary>
        [Input("name")]
        public string? Name { get; set; }

        /// <summary>
        /// The registry Ocid.
        /// </summary>
        [Input("registryId", required: true)]
        public string RegistryId { get; set; } = null!;

        /// <summary>
        /// Type of the object to filter the results with.
        /// </summary>
        [Input("type")]
        public string? Type { get; set; }

        public GetRegistryConnectionsArgs()
        {
        }
    }

    public sealed class GetRegistryConnectionsInvokeArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// Used to filter by the data asset key of the object.
        /// </summary>
        [Input("dataAssetKey", required: true)]
        public Input<string> DataAssetKey { get; set; } = null!;

        /// <summary>
        /// If value is FAVORITES_ONLY, then only objects marked as favorite by the requesting user will be included in result. If value is NON_FAVORITES_ONLY, then objects marked as favorites by the requesting user will be skipped. If value is ALL or if not specified, all objects, irrespective of favorites or not will be returned. Default is ALL.
        /// </summary>
        [Input("favoritesQueryParam")]
        public Input<string>? FavoritesQueryParam { get; set; }

        [Input("fields")]
        private InputList<string>? _fields;

        /// <summary>
        /// Specifies the fields to get for an object.
        /// </summary>
        public InputList<string> Fields
        {
            get => _fields ?? (_fields = new InputList<string>());
            set => _fields = value;
        }

        [Input("filters")]
        private InputList<Inputs.GetRegistryConnectionsFilterInputArgs>? _filters;
        public InputList<Inputs.GetRegistryConnectionsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetRegistryConnectionsFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// Used to filter by the name of the object.
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// The registry Ocid.
        /// </summary>
        [Input("registryId", required: true)]
        public Input<string> RegistryId { get; set; } = null!;

        /// <summary>
        /// Type of the object to filter the results with.
        /// </summary>
        [Input("type")]
        public Input<string>? Type { get; set; }

        public GetRegistryConnectionsInvokeArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetRegistryConnectionsResult
    {
        /// <summary>
        /// The list of connection_summary_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetRegistryConnectionsConnectionSummaryCollectionResult> ConnectionSummaryCollections;
        public readonly string DataAssetKey;
        public readonly string? FavoritesQueryParam;
        public readonly ImmutableArray<string> Fields;
        public readonly ImmutableArray<Outputs.GetRegistryConnectionsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
        /// </summary>
        public readonly string? Name;
        public readonly string RegistryId;
        /// <summary>
        /// Specific Connection Type
        /// </summary>
        public readonly string? Type;

        [OutputConstructor]
        private GetRegistryConnectionsResult(
            ImmutableArray<Outputs.GetRegistryConnectionsConnectionSummaryCollectionResult> connectionSummaryCollections,

            string dataAssetKey,

            string? favoritesQueryParam,

            ImmutableArray<string> fields,

            ImmutableArray<Outputs.GetRegistryConnectionsFilterResult> filters,

            string id,

            string? name,

            string registryId,

            string? type)
        {
            ConnectionSummaryCollections = connectionSummaryCollections;
            DataAssetKey = dataAssetKey;
            FavoritesQueryParam = favoritesQueryParam;
            Fields = fields;
            Filters = filters;
            Id = id;
            Name = name;
            RegistryId = registryId;
            Type = type;
        }
    }
}
