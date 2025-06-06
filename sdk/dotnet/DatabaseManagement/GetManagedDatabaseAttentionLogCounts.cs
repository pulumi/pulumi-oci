// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseManagement
{
    public static class GetManagedDatabaseAttentionLogCounts
    {
        /// <summary>
        /// This data source provides the list of Managed Database Attention Log Counts in Oracle Cloud Infrastructure Database Management service.
        /// 
        /// Get the counts of attention logs for the specified Managed Database.
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
        ///     var testManagedDatabaseAttentionLogCounts = Oci.DatabaseManagement.GetManagedDatabaseAttentionLogCounts.Invoke(new()
        ///     {
        ///         ManagedDatabaseId = testManagedDatabase.Id,
        ///         GroupBy = managedDatabaseAttentionLogCountGroupBy,
        ///         IsRegularExpression = managedDatabaseAttentionLogCountIsRegularExpression,
        ///         LogSearchText = managedDatabaseAttentionLogCountLogSearchText,
        ///         TimeGreaterThanOrEqualTo = managedDatabaseAttentionLogCountTimeGreaterThanOrEqualTo,
        ///         TimeLessThanOrEqualTo = managedDatabaseAttentionLogCountTimeLessThanOrEqualTo,
        ///         TypeFilter = managedDatabaseAttentionLogCountTypeFilter,
        ///         UrgencyFilter = managedDatabaseAttentionLogCountUrgencyFilter,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetManagedDatabaseAttentionLogCountsResult> InvokeAsync(GetManagedDatabaseAttentionLogCountsArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetManagedDatabaseAttentionLogCountsResult>("oci:DatabaseManagement/getManagedDatabaseAttentionLogCounts:getManagedDatabaseAttentionLogCounts", args ?? new GetManagedDatabaseAttentionLogCountsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Managed Database Attention Log Counts in Oracle Cloud Infrastructure Database Management service.
        /// 
        /// Get the counts of attention logs for the specified Managed Database.
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
        ///     var testManagedDatabaseAttentionLogCounts = Oci.DatabaseManagement.GetManagedDatabaseAttentionLogCounts.Invoke(new()
        ///     {
        ///         ManagedDatabaseId = testManagedDatabase.Id,
        ///         GroupBy = managedDatabaseAttentionLogCountGroupBy,
        ///         IsRegularExpression = managedDatabaseAttentionLogCountIsRegularExpression,
        ///         LogSearchText = managedDatabaseAttentionLogCountLogSearchText,
        ///         TimeGreaterThanOrEqualTo = managedDatabaseAttentionLogCountTimeGreaterThanOrEqualTo,
        ///         TimeLessThanOrEqualTo = managedDatabaseAttentionLogCountTimeLessThanOrEqualTo,
        ///         TypeFilter = managedDatabaseAttentionLogCountTypeFilter,
        ///         UrgencyFilter = managedDatabaseAttentionLogCountUrgencyFilter,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetManagedDatabaseAttentionLogCountsResult> Invoke(GetManagedDatabaseAttentionLogCountsInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetManagedDatabaseAttentionLogCountsResult>("oci:DatabaseManagement/getManagedDatabaseAttentionLogCounts:getManagedDatabaseAttentionLogCounts", args ?? new GetManagedDatabaseAttentionLogCountsInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Managed Database Attention Log Counts in Oracle Cloud Infrastructure Database Management service.
        /// 
        /// Get the counts of attention logs for the specified Managed Database.
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
        ///     var testManagedDatabaseAttentionLogCounts = Oci.DatabaseManagement.GetManagedDatabaseAttentionLogCounts.Invoke(new()
        ///     {
        ///         ManagedDatabaseId = testManagedDatabase.Id,
        ///         GroupBy = managedDatabaseAttentionLogCountGroupBy,
        ///         IsRegularExpression = managedDatabaseAttentionLogCountIsRegularExpression,
        ///         LogSearchText = managedDatabaseAttentionLogCountLogSearchText,
        ///         TimeGreaterThanOrEqualTo = managedDatabaseAttentionLogCountTimeGreaterThanOrEqualTo,
        ///         TimeLessThanOrEqualTo = managedDatabaseAttentionLogCountTimeLessThanOrEqualTo,
        ///         TypeFilter = managedDatabaseAttentionLogCountTypeFilter,
        ///         UrgencyFilter = managedDatabaseAttentionLogCountUrgencyFilter,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetManagedDatabaseAttentionLogCountsResult> Invoke(GetManagedDatabaseAttentionLogCountsInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetManagedDatabaseAttentionLogCountsResult>("oci:DatabaseManagement/getManagedDatabaseAttentionLogCounts:getManagedDatabaseAttentionLogCounts", args ?? new GetManagedDatabaseAttentionLogCountsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetManagedDatabaseAttentionLogCountsArgs : global::Pulumi.InvokeArgs
    {
        [Input("filters")]
        private List<Inputs.GetManagedDatabaseAttentionLogCountsFilterArgs>? _filters;
        public List<Inputs.GetManagedDatabaseAttentionLogCountsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetManagedDatabaseAttentionLogCountsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The optional parameter used to group different attention logs.
        /// </summary>
        [Input("groupBy")]
        public string? GroupBy { get; set; }

        /// <summary>
        /// The flag to indicate whether the search text is regular expression or not.
        /// </summary>
        [Input("isRegularExpression")]
        public bool? IsRegularExpression { get; set; }

        /// <summary>
        /// The optional query parameter to filter the attention or alert logs by search text.
        /// </summary>
        [Input("logSearchText")]
        public string? LogSearchText { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
        /// </summary>
        [Input("managedDatabaseId", required: true)]
        public string ManagedDatabaseId { get; set; } = null!;

        /// <summary>
        /// The optional greater than or equal to timestamp to filter the logs.
        /// </summary>
        [Input("timeGreaterThanOrEqualTo")]
        public string? TimeGreaterThanOrEqualTo { get; set; }

        /// <summary>
        /// The optional less than or equal to timestamp to filter the logs.
        /// </summary>
        [Input("timeLessThanOrEqualTo")]
        public string? TimeLessThanOrEqualTo { get; set; }

        /// <summary>
        /// The optional parameter to filter the attention or alert logs by type.
        /// </summary>
        [Input("typeFilter")]
        public string? TypeFilter { get; set; }

        /// <summary>
        /// The optional parameter to filter the attention logs by urgency.
        /// </summary>
        [Input("urgencyFilter")]
        public string? UrgencyFilter { get; set; }

        public GetManagedDatabaseAttentionLogCountsArgs()
        {
        }
        public static new GetManagedDatabaseAttentionLogCountsArgs Empty => new GetManagedDatabaseAttentionLogCountsArgs();
    }

    public sealed class GetManagedDatabaseAttentionLogCountsInvokeArgs : global::Pulumi.InvokeArgs
    {
        [Input("filters")]
        private InputList<Inputs.GetManagedDatabaseAttentionLogCountsFilterInputArgs>? _filters;
        public InputList<Inputs.GetManagedDatabaseAttentionLogCountsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetManagedDatabaseAttentionLogCountsFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The optional parameter used to group different attention logs.
        /// </summary>
        [Input("groupBy")]
        public Input<string>? GroupBy { get; set; }

        /// <summary>
        /// The flag to indicate whether the search text is regular expression or not.
        /// </summary>
        [Input("isRegularExpression")]
        public Input<bool>? IsRegularExpression { get; set; }

        /// <summary>
        /// The optional query parameter to filter the attention or alert logs by search text.
        /// </summary>
        [Input("logSearchText")]
        public Input<string>? LogSearchText { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
        /// </summary>
        [Input("managedDatabaseId", required: true)]
        public Input<string> ManagedDatabaseId { get; set; } = null!;

        /// <summary>
        /// The optional greater than or equal to timestamp to filter the logs.
        /// </summary>
        [Input("timeGreaterThanOrEqualTo")]
        public Input<string>? TimeGreaterThanOrEqualTo { get; set; }

        /// <summary>
        /// The optional less than or equal to timestamp to filter the logs.
        /// </summary>
        [Input("timeLessThanOrEqualTo")]
        public Input<string>? TimeLessThanOrEqualTo { get; set; }

        /// <summary>
        /// The optional parameter to filter the attention or alert logs by type.
        /// </summary>
        [Input("typeFilter")]
        public Input<string>? TypeFilter { get; set; }

        /// <summary>
        /// The optional parameter to filter the attention logs by urgency.
        /// </summary>
        [Input("urgencyFilter")]
        public Input<string>? UrgencyFilter { get; set; }

        public GetManagedDatabaseAttentionLogCountsInvokeArgs()
        {
        }
        public static new GetManagedDatabaseAttentionLogCountsInvokeArgs Empty => new GetManagedDatabaseAttentionLogCountsInvokeArgs();
    }


    [OutputType]
    public sealed class GetManagedDatabaseAttentionLogCountsResult
    {
        /// <summary>
        /// The list of attention_log_counts_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetManagedDatabaseAttentionLogCountsAttentionLogCountsCollectionResult> AttentionLogCountsCollections;
        public readonly ImmutableArray<Outputs.GetManagedDatabaseAttentionLogCountsFilterResult> Filters;
        public readonly string? GroupBy;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly bool? IsRegularExpression;
        public readonly string? LogSearchText;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
        /// </summary>
        public readonly string ManagedDatabaseId;
        public readonly string? TimeGreaterThanOrEqualTo;
        public readonly string? TimeLessThanOrEqualTo;
        public readonly string? TypeFilter;
        public readonly string? UrgencyFilter;

        [OutputConstructor]
        private GetManagedDatabaseAttentionLogCountsResult(
            ImmutableArray<Outputs.GetManagedDatabaseAttentionLogCountsAttentionLogCountsCollectionResult> attentionLogCountsCollections,

            ImmutableArray<Outputs.GetManagedDatabaseAttentionLogCountsFilterResult> filters,

            string? groupBy,

            string id,

            bool? isRegularExpression,

            string? logSearchText,

            string managedDatabaseId,

            string? timeGreaterThanOrEqualTo,

            string? timeLessThanOrEqualTo,

            string? typeFilter,

            string? urgencyFilter)
        {
            AttentionLogCountsCollections = attentionLogCountsCollections;
            Filters = filters;
            GroupBy = groupBy;
            Id = id;
            IsRegularExpression = isRegularExpression;
            LogSearchText = logSearchText;
            ManagedDatabaseId = managedDatabaseId;
            TimeGreaterThanOrEqualTo = timeGreaterThanOrEqualTo;
            TimeLessThanOrEqualTo = timeLessThanOrEqualTo;
            TypeFilter = typeFilter;
            UrgencyFilter = urgencyFilter;
        }
    }
}
