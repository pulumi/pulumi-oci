// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CloudGuard
{
    public static class GetDataSources
    {
        /// <summary>
        /// This data source provides the list of Data Sources in Oracle Cloud Infrastructure Cloud Guard service.
        /// 
        /// Returns a list of all Data Sources in a compartment
        /// 
        /// The ListDataSources operation returns only the data Sources in `compartmentId` passed.
        /// The list does not include any subcompartments of the compartmentId passed.
        /// 
        /// The parameter `accessLevel` specifies whether to return only those compartments for which the
        /// requestor has INSPECT permissions on at least one resource directly
        /// or indirectly (ACCESSIBLE) (the resource can be in a subcompartment) or to return Not Authorized if
        /// Principal doesn't have access to even one of the child compartments. This is valid only when
        /// `compartmentIdInSubtree` is set to `true`.
        /// 
        /// The parameter `compartmentIdInSubtree` applies when you perform ListdataSources on the
        /// `compartmentId` passed and when it is set to true, the entire hierarchy of compartments can be returned.
        /// To get a full list of all compartments and subcompartments in the tenancy (root compartment),
        /// set the parameter `compartmentIdInSubtree` to true and `accessLevel` to ACCESSIBLE.
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
        ///     var testDataSources = Oci.CloudGuard.GetDataSources.Invoke(new()
        ///     {
        ///         CompartmentId = @var.Compartment_id,
        ///         AccessLevel = @var.Data_source_access_level,
        ///         CompartmentIdInSubtree = @var.Data_source_compartment_id_in_subtree,
        ///         DataSourceFeedProvider = @var.Data_source_data_source_feed_provider,
        ///         DisplayName = @var.Data_source_display_name,
        ///         LoggingQueryType = @var.Data_source_logging_query_type,
        ///         State = @var.Data_source_state,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetDataSourcesResult> InvokeAsync(GetDataSourcesArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetDataSourcesResult>("oci:CloudGuard/getDataSources:getDataSources", args ?? new GetDataSourcesArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Data Sources in Oracle Cloud Infrastructure Cloud Guard service.
        /// 
        /// Returns a list of all Data Sources in a compartment
        /// 
        /// The ListDataSources operation returns only the data Sources in `compartmentId` passed.
        /// The list does not include any subcompartments of the compartmentId passed.
        /// 
        /// The parameter `accessLevel` specifies whether to return only those compartments for which the
        /// requestor has INSPECT permissions on at least one resource directly
        /// or indirectly (ACCESSIBLE) (the resource can be in a subcompartment) or to return Not Authorized if
        /// Principal doesn't have access to even one of the child compartments. This is valid only when
        /// `compartmentIdInSubtree` is set to `true`.
        /// 
        /// The parameter `compartmentIdInSubtree` applies when you perform ListdataSources on the
        /// `compartmentId` passed and when it is set to true, the entire hierarchy of compartments can be returned.
        /// To get a full list of all compartments and subcompartments in the tenancy (root compartment),
        /// set the parameter `compartmentIdInSubtree` to true and `accessLevel` to ACCESSIBLE.
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
        ///     var testDataSources = Oci.CloudGuard.GetDataSources.Invoke(new()
        ///     {
        ///         CompartmentId = @var.Compartment_id,
        ///         AccessLevel = @var.Data_source_access_level,
        ///         CompartmentIdInSubtree = @var.Data_source_compartment_id_in_subtree,
        ///         DataSourceFeedProvider = @var.Data_source_data_source_feed_provider,
        ///         DisplayName = @var.Data_source_display_name,
        ///         LoggingQueryType = @var.Data_source_logging_query_type,
        ///         State = @var.Data_source_state,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetDataSourcesResult> Invoke(GetDataSourcesInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetDataSourcesResult>("oci:CloudGuard/getDataSources:getDataSources", args ?? new GetDataSourcesInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetDataSourcesArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// Valid values are `RESTRICTED` and `ACCESSIBLE`. Default is `RESTRICTED`. Setting this to `ACCESSIBLE` returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to `RESTRICTED` permissions are checked and no partial results are displayed.
        /// </summary>
        [Input("accessLevel")]
        public string? AccessLevel { get; set; }

        /// <summary>
        /// The ID of the compartment in which to list resources.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned depending on the the setting of `accessLevel`.
        /// </summary>
        [Input("compartmentIdInSubtree")]
        public bool? CompartmentIdInSubtree { get; set; }

        /// <summary>
        /// A filter to return only resources their feedProvider matches the given DataSourceFeedProvider.
        /// </summary>
        [Input("dataSourceFeedProvider")]
        public string? DataSourceFeedProvider { get; set; }

        /// <summary>
        /// A filter to return only resources that match the entire display name given.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetDataSourcesFilterArgs>? _filters;
        public List<Inputs.GetDataSourcesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetDataSourcesFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only resources their query type matches the given LoggingQueryType.
        /// </summary>
        [Input("loggingQueryType")]
        public string? LoggingQueryType { get; set; }

        /// <summary>
        /// The field life cycle state. Only one state can be provided. Default value for state is active. If no value is specified state is active.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        public GetDataSourcesArgs()
        {
        }
        public static new GetDataSourcesArgs Empty => new GetDataSourcesArgs();
    }

    public sealed class GetDataSourcesInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// Valid values are `RESTRICTED` and `ACCESSIBLE`. Default is `RESTRICTED`. Setting this to `ACCESSIBLE` returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to `RESTRICTED` permissions are checked and no partial results are displayed.
        /// </summary>
        [Input("accessLevel")]
        public Input<string>? AccessLevel { get; set; }

        /// <summary>
        /// The ID of the compartment in which to list resources.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned depending on the the setting of `accessLevel`.
        /// </summary>
        [Input("compartmentIdInSubtree")]
        public Input<bool>? CompartmentIdInSubtree { get; set; }

        /// <summary>
        /// A filter to return only resources their feedProvider matches the given DataSourceFeedProvider.
        /// </summary>
        [Input("dataSourceFeedProvider")]
        public Input<string>? DataSourceFeedProvider { get; set; }

        /// <summary>
        /// A filter to return only resources that match the entire display name given.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetDataSourcesFilterInputArgs>? _filters;
        public InputList<Inputs.GetDataSourcesFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetDataSourcesFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only resources their query type matches the given LoggingQueryType.
        /// </summary>
        [Input("loggingQueryType")]
        public Input<string>? LoggingQueryType { get; set; }

        /// <summary>
        /// The field life cycle state. Only one state can be provided. Default value for state is active. If no value is specified state is active.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        public GetDataSourcesInvokeArgs()
        {
        }
        public static new GetDataSourcesInvokeArgs Empty => new GetDataSourcesInvokeArgs();
    }


    [OutputType]
    public sealed class GetDataSourcesResult
    {
        public readonly string? AccessLevel;
        /// <summary>
        /// CompartmentId of Data source.
        /// </summary>
        public readonly string CompartmentId;
        public readonly bool? CompartmentIdInSubtree;
        /// <summary>
        /// The list of data_source_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDataSourcesDataSourceCollectionResult> DataSourceCollections;
        /// <summary>
        /// Possible type of dataSourceFeed Provider(LoggingQuery)
        /// </summary>
        public readonly string? DataSourceFeedProvider;
        /// <summary>
        /// DisplayName of Data source.
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetDataSourcesFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Logging query type for data source (Sighting/Insight)
        /// </summary>
        public readonly string? LoggingQueryType;
        /// <summary>
        /// The current state of the resource.
        /// </summary>
        public readonly string? State;

        [OutputConstructor]
        private GetDataSourcesResult(
            string? accessLevel,

            string compartmentId,

            bool? compartmentIdInSubtree,

            ImmutableArray<Outputs.GetDataSourcesDataSourceCollectionResult> dataSourceCollections,

            string? dataSourceFeedProvider,

            string? displayName,

            ImmutableArray<Outputs.GetDataSourcesFilterResult> filters,

            string id,

            string? loggingQueryType,

            string? state)
        {
            AccessLevel = accessLevel;
            CompartmentId = compartmentId;
            CompartmentIdInSubtree = compartmentIdInSubtree;
            DataSourceCollections = dataSourceCollections;
            DataSourceFeedProvider = dataSourceFeedProvider;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            LoggingQueryType = loggingQueryType;
            State = state;
        }
    }
}