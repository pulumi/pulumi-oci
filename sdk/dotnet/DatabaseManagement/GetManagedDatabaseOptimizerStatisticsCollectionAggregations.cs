// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseManagement
{
    public static class GetManagedDatabaseOptimizerStatisticsCollectionAggregations
    {
        /// <summary>
        /// This data source provides the list of Managed Database Optimizer Statistics Collection Aggregations in Oracle Cloud Infrastructure Database Management service.
        /// 
        /// Gets a list of the optimizer statistics collection operations per hour, grouped by task or object status for the specified Managed Database.
        /// You must specify a value for the GroupByQueryParam to determine whether the data should be grouped by task status or task object status.
        /// Optionally, you can specify a date-time range (of seven days) to obtain collection aggregations within the specified time range.
        /// If the date-time range is not specified, then the operations in the last seven days are listed.
        /// You can further filter the results by providing the optional type of TaskTypeQueryParam.
        /// If the task type if not provided, then both Auto and Manual tasks are considered for aggregation.
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
        ///     var testManagedDatabaseOptimizerStatisticsCollectionAggregations = Oci.DatabaseManagement.GetManagedDatabaseOptimizerStatisticsCollectionAggregations.Invoke(new()
        ///     {
        ///         GroupType = managedDatabaseOptimizerStatisticsCollectionAggregationGroupType,
        ///         ManagedDatabaseId = testManagedDatabase.Id,
        ///         EndTimeLessThanOrEqualTo = managedDatabaseOptimizerStatisticsCollectionAggregationEndTimeLessThanOrEqualTo,
        ///         StartTimeGreaterThanOrEqualTo = managedDatabaseOptimizerStatisticsCollectionAggregationStartTimeGreaterThanOrEqualTo,
        ///         TaskType = managedDatabaseOptimizerStatisticsCollectionAggregationTaskType,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetManagedDatabaseOptimizerStatisticsCollectionAggregationsResult> InvokeAsync(GetManagedDatabaseOptimizerStatisticsCollectionAggregationsArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetManagedDatabaseOptimizerStatisticsCollectionAggregationsResult>("oci:DatabaseManagement/getManagedDatabaseOptimizerStatisticsCollectionAggregations:getManagedDatabaseOptimizerStatisticsCollectionAggregations", args ?? new GetManagedDatabaseOptimizerStatisticsCollectionAggregationsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Managed Database Optimizer Statistics Collection Aggregations in Oracle Cloud Infrastructure Database Management service.
        /// 
        /// Gets a list of the optimizer statistics collection operations per hour, grouped by task or object status for the specified Managed Database.
        /// You must specify a value for the GroupByQueryParam to determine whether the data should be grouped by task status or task object status.
        /// Optionally, you can specify a date-time range (of seven days) to obtain collection aggregations within the specified time range.
        /// If the date-time range is not specified, then the operations in the last seven days are listed.
        /// You can further filter the results by providing the optional type of TaskTypeQueryParam.
        /// If the task type if not provided, then both Auto and Manual tasks are considered for aggregation.
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
        ///     var testManagedDatabaseOptimizerStatisticsCollectionAggregations = Oci.DatabaseManagement.GetManagedDatabaseOptimizerStatisticsCollectionAggregations.Invoke(new()
        ///     {
        ///         GroupType = managedDatabaseOptimizerStatisticsCollectionAggregationGroupType,
        ///         ManagedDatabaseId = testManagedDatabase.Id,
        ///         EndTimeLessThanOrEqualTo = managedDatabaseOptimizerStatisticsCollectionAggregationEndTimeLessThanOrEqualTo,
        ///         StartTimeGreaterThanOrEqualTo = managedDatabaseOptimizerStatisticsCollectionAggregationStartTimeGreaterThanOrEqualTo,
        ///         TaskType = managedDatabaseOptimizerStatisticsCollectionAggregationTaskType,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetManagedDatabaseOptimizerStatisticsCollectionAggregationsResult> Invoke(GetManagedDatabaseOptimizerStatisticsCollectionAggregationsInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetManagedDatabaseOptimizerStatisticsCollectionAggregationsResult>("oci:DatabaseManagement/getManagedDatabaseOptimizerStatisticsCollectionAggregations:getManagedDatabaseOptimizerStatisticsCollectionAggregations", args ?? new GetManagedDatabaseOptimizerStatisticsCollectionAggregationsInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Managed Database Optimizer Statistics Collection Aggregations in Oracle Cloud Infrastructure Database Management service.
        /// 
        /// Gets a list of the optimizer statistics collection operations per hour, grouped by task or object status for the specified Managed Database.
        /// You must specify a value for the GroupByQueryParam to determine whether the data should be grouped by task status or task object status.
        /// Optionally, you can specify a date-time range (of seven days) to obtain collection aggregations within the specified time range.
        /// If the date-time range is not specified, then the operations in the last seven days are listed.
        /// You can further filter the results by providing the optional type of TaskTypeQueryParam.
        /// If the task type if not provided, then both Auto and Manual tasks are considered for aggregation.
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
        ///     var testManagedDatabaseOptimizerStatisticsCollectionAggregations = Oci.DatabaseManagement.GetManagedDatabaseOptimizerStatisticsCollectionAggregations.Invoke(new()
        ///     {
        ///         GroupType = managedDatabaseOptimizerStatisticsCollectionAggregationGroupType,
        ///         ManagedDatabaseId = testManagedDatabase.Id,
        ///         EndTimeLessThanOrEqualTo = managedDatabaseOptimizerStatisticsCollectionAggregationEndTimeLessThanOrEqualTo,
        ///         StartTimeGreaterThanOrEqualTo = managedDatabaseOptimizerStatisticsCollectionAggregationStartTimeGreaterThanOrEqualTo,
        ///         TaskType = managedDatabaseOptimizerStatisticsCollectionAggregationTaskType,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetManagedDatabaseOptimizerStatisticsCollectionAggregationsResult> Invoke(GetManagedDatabaseOptimizerStatisticsCollectionAggregationsInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetManagedDatabaseOptimizerStatisticsCollectionAggregationsResult>("oci:DatabaseManagement/getManagedDatabaseOptimizerStatisticsCollectionAggregations:getManagedDatabaseOptimizerStatisticsCollectionAggregations", args ?? new GetManagedDatabaseOptimizerStatisticsCollectionAggregationsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetManagedDatabaseOptimizerStatisticsCollectionAggregationsArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The end time of the time range to retrieve the optimizer statistics of a Managed Database in UTC in ISO-8601 format, which is "yyyy-MM-dd'T'hh:mm:ss.sss'Z'".
        /// </summary>
        [Input("endTimeLessThanOrEqualTo")]
        public string? EndTimeLessThanOrEqualTo { get; set; }

        [Input("filters")]
        private List<Inputs.GetManagedDatabaseOptimizerStatisticsCollectionAggregationsFilterArgs>? _filters;
        public List<Inputs.GetManagedDatabaseOptimizerStatisticsCollectionAggregationsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetManagedDatabaseOptimizerStatisticsCollectionAggregationsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The optimizer statistics tasks grouped by type.
        /// </summary>
        [Input("groupType", required: true)]
        public string GroupType { get; set; } = null!;

        [Input("limit")]
        public int? Limit { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
        /// </summary>
        [Input("managedDatabaseId", required: true)]
        public string ManagedDatabaseId { get; set; } = null!;

        /// <summary>
        /// The start time of the time range to retrieve the optimizer statistics of a Managed Database in UTC in ISO-8601 format, which is "yyyy-MM-dd'T'hh:mm:ss.sss'Z'".
        /// </summary>
        [Input("startTimeGreaterThanOrEqualTo")]
        public string? StartTimeGreaterThanOrEqualTo { get; set; }

        /// <summary>
        /// The filter types of the optimizer statistics tasks.
        /// </summary>
        [Input("taskType")]
        public string? TaskType { get; set; }

        public GetManagedDatabaseOptimizerStatisticsCollectionAggregationsArgs()
        {
        }
        public static new GetManagedDatabaseOptimizerStatisticsCollectionAggregationsArgs Empty => new GetManagedDatabaseOptimizerStatisticsCollectionAggregationsArgs();
    }

    public sealed class GetManagedDatabaseOptimizerStatisticsCollectionAggregationsInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The end time of the time range to retrieve the optimizer statistics of a Managed Database in UTC in ISO-8601 format, which is "yyyy-MM-dd'T'hh:mm:ss.sss'Z'".
        /// </summary>
        [Input("endTimeLessThanOrEqualTo")]
        public Input<string>? EndTimeLessThanOrEqualTo { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetManagedDatabaseOptimizerStatisticsCollectionAggregationsFilterInputArgs>? _filters;
        public InputList<Inputs.GetManagedDatabaseOptimizerStatisticsCollectionAggregationsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetManagedDatabaseOptimizerStatisticsCollectionAggregationsFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The optimizer statistics tasks grouped by type.
        /// </summary>
        [Input("groupType", required: true)]
        public Input<string> GroupType { get; set; } = null!;

        [Input("limit")]
        public Input<int>? Limit { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
        /// </summary>
        [Input("managedDatabaseId", required: true)]
        public Input<string> ManagedDatabaseId { get; set; } = null!;

        /// <summary>
        /// The start time of the time range to retrieve the optimizer statistics of a Managed Database in UTC in ISO-8601 format, which is "yyyy-MM-dd'T'hh:mm:ss.sss'Z'".
        /// </summary>
        [Input("startTimeGreaterThanOrEqualTo")]
        public Input<string>? StartTimeGreaterThanOrEqualTo { get; set; }

        /// <summary>
        /// The filter types of the optimizer statistics tasks.
        /// </summary>
        [Input("taskType")]
        public Input<string>? TaskType { get; set; }

        public GetManagedDatabaseOptimizerStatisticsCollectionAggregationsInvokeArgs()
        {
        }
        public static new GetManagedDatabaseOptimizerStatisticsCollectionAggregationsInvokeArgs Empty => new GetManagedDatabaseOptimizerStatisticsCollectionAggregationsInvokeArgs();
    }


    [OutputType]
    public sealed class GetManagedDatabaseOptimizerStatisticsCollectionAggregationsResult
    {
        public readonly string? EndTimeLessThanOrEqualTo;
        public readonly ImmutableArray<Outputs.GetManagedDatabaseOptimizerStatisticsCollectionAggregationsFilterResult> Filters;
        public readonly string GroupType;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly int? Limit;
        public readonly string ManagedDatabaseId;
        /// <summary>
        /// The list of optimizer_statistics_collection_aggregations_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetManagedDatabaseOptimizerStatisticsCollectionAggregationsOptimizerStatisticsCollectionAggregationsCollectionResult> OptimizerStatisticsCollectionAggregationsCollections;
        public readonly string? StartTimeGreaterThanOrEqualTo;
        public readonly string? TaskType;

        [OutputConstructor]
        private GetManagedDatabaseOptimizerStatisticsCollectionAggregationsResult(
            string? endTimeLessThanOrEqualTo,

            ImmutableArray<Outputs.GetManagedDatabaseOptimizerStatisticsCollectionAggregationsFilterResult> filters,

            string groupType,

            string id,

            int? limit,

            string managedDatabaseId,

            ImmutableArray<Outputs.GetManagedDatabaseOptimizerStatisticsCollectionAggregationsOptimizerStatisticsCollectionAggregationsCollectionResult> optimizerStatisticsCollectionAggregationsCollections,

            string? startTimeGreaterThanOrEqualTo,

            string? taskType)
        {
            EndTimeLessThanOrEqualTo = endTimeLessThanOrEqualTo;
            Filters = filters;
            GroupType = groupType;
            Id = id;
            Limit = limit;
            ManagedDatabaseId = managedDatabaseId;
            OptimizerStatisticsCollectionAggregationsCollections = optimizerStatisticsCollectionAggregationsCollections;
            StartTimeGreaterThanOrEqualTo = startTimeGreaterThanOrEqualTo;
            TaskType = taskType;
        }
    }
}
