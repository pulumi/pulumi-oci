// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataSafe
{
    public static class GetReportDefinition
    {
        /// <summary>
        /// This data source provides details about a specific Report Definition resource in Oracle Cloud Infrastructure Data Safe service.
        /// 
        /// Gets the details of report definition specified by the identifier
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
        ///     var testReportDefinition = Oci.DataSafe.GetReportDefinition.Invoke(new()
        ///     {
        ///         ReportDefinitionId = testReportDefinitionOciDataSafeReportDefinition.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetReportDefinitionResult> InvokeAsync(GetReportDefinitionArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetReportDefinitionResult>("oci:DataSafe/getReportDefinition:getReportDefinition", args ?? new GetReportDefinitionArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Report Definition resource in Oracle Cloud Infrastructure Data Safe service.
        /// 
        /// Gets the details of report definition specified by the identifier
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
        ///     var testReportDefinition = Oci.DataSafe.GetReportDefinition.Invoke(new()
        ///     {
        ///         ReportDefinitionId = testReportDefinitionOciDataSafeReportDefinition.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetReportDefinitionResult> Invoke(GetReportDefinitionInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetReportDefinitionResult>("oci:DataSafe/getReportDefinition:getReportDefinition", args ?? new GetReportDefinitionInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Report Definition resource in Oracle Cloud Infrastructure Data Safe service.
        /// 
        /// Gets the details of report definition specified by the identifier
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
        ///     var testReportDefinition = Oci.DataSafe.GetReportDefinition.Invoke(new()
        ///     {
        ///         ReportDefinitionId = testReportDefinitionOciDataSafeReportDefinition.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetReportDefinitionResult> Invoke(GetReportDefinitionInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetReportDefinitionResult>("oci:DataSafe/getReportDefinition:getReportDefinition", args ?? new GetReportDefinitionInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetReportDefinitionArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// Unique report definition identifier
        /// </summary>
        [Input("reportDefinitionId", required: true)]
        public string ReportDefinitionId { get; set; } = null!;

        public GetReportDefinitionArgs()
        {
        }
        public static new GetReportDefinitionArgs Empty => new GetReportDefinitionArgs();
    }

    public sealed class GetReportDefinitionInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// Unique report definition identifier
        /// </summary>
        [Input("reportDefinitionId", required: true)]
        public Input<string> ReportDefinitionId { get; set; } = null!;

        public GetReportDefinitionInvokeArgs()
        {
        }
        public static new GetReportDefinitionInvokeArgs Empty => new GetReportDefinitionInvokeArgs();
    }


    [OutputType]
    public sealed class GetReportDefinitionResult
    {
        /// <summary>
        /// Specifies the name of the category that this report belongs to.
        /// </summary>
        public readonly string Category;
        /// <summary>
        /// An array of columnFilter objects. A columnFilter object stores all information about a column filter including field name, an operator, one or more expressions, if the filter is enabled, or if the filter is hidden.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetReportDefinitionColumnFilterResult> ColumnFilters;
        /// <summary>
        /// An array of column objects in the order (left to right) displayed in the report. A column object stores all information about a column, including the name displayed on the UI, corresponding field name in the data source, data type of the column, and column visibility (if the column is visible to the user).
        /// </summary>
        public readonly ImmutableArray<Outputs.GetReportDefinitionColumnInfoResult> ColumnInfos;
        /// <summary>
        /// An array of column sorting objects. Each column sorting object stores the column name to be sorted and if the sorting is in ascending order; sorting is done by the first column in the array, then by the second column in the array, etc.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetReportDefinitionColumnSortingResult> ColumnSortings;
        /// <summary>
        /// The OCID of the compartment containing the report definition.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The list of the data protection regulations/standards used in the report that will help demonstrate compliance.
        /// </summary>
        public readonly ImmutableArray<string> ComplianceStandards;
        /// <summary>
        /// Specifies the name of a resource that provides data for the report. For example alerts, events.
        /// </summary>
        public readonly string DataSource;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm) Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// A description of the report definition.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// Name of the report definition.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Specifies the order in which the summary must be displayed.
        /// </summary>
        public readonly int DisplayOrder;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// The OCID of the report definition.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Signifies whether the definition is seeded or user defined. Values can either be 'true' or 'false'.
        /// </summary>
        public readonly bool IsSeeded;
        /// <summary>
        /// Details about the current state of the report definition in Data Safe.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// The OCID of the parent report definition. In the case of seeded report definition, this is same as definition OCID.
        /// </summary>
        public readonly string ParentId;
        /// <summary>
        /// The time span for the records in the report to be scheduled. &lt;period-value&gt;&lt;period&gt; Allowed period strings - "H","D","M","Y" Each of the above fields potentially introduce constraints. A workRequest is created only when period-value satisfies all the constraints. Constraints introduced: 1. period = H (The allowed range for period-value is [1, 23]) 2. period = D (The allowed range for period-value is [1, 30]) 3. period = M (The allowed range for period-value is [1, 11]) 4. period = Y (The minimum period-value is 1)
        /// </summary>
        public readonly string RecordTimeSpan;
        public readonly string ReportDefinitionId;
        /// <summary>
        /// The schedule to generate the report periodically in the specified format: &lt;version-string&gt;;&lt;version-specific-schedule&gt;
        /// </summary>
        public readonly string Schedule;
        /// <summary>
        /// The OCID of the compartment in which the scheduled resource will be created.
        /// </summary>
        public readonly string ScheduledReportCompartmentId;
        /// <summary>
        /// Specifies the format of the report ( either .xls or .pdf or .json)
        /// </summary>
        public readonly string ScheduledReportMimeType;
        /// <summary>
        /// The name of the report to be scheduled.
        /// </summary>
        public readonly string ScheduledReportName;
        /// <summary>
        /// Specifies the limit on the number of rows in the report.
        /// </summary>
        public readonly int ScheduledReportRowLimit;
        /// <summary>
        /// Additional scim filters used to get the specific summary.
        /// </summary>
        public readonly string ScimFilter;
        /// <summary>
        /// The current state of the report.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// An array of report summary objects in the order (left to right)  displayed in the report.  A  report summary object stores all information about summary of report to be displayed, including the name displayed on UI, the display order, corresponding group by and count of values, summary visibility (if the summary is visible to user).
        /// </summary>
        public readonly ImmutableArray<Outputs.GetReportDefinitionSummaryResult> Summaries;
        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> SystemTags;
        /// <summary>
        /// Specifies the date and time the report definition was created.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The date and time the report definition was updated.
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetReportDefinitionResult(
            string category,

            ImmutableArray<Outputs.GetReportDefinitionColumnFilterResult> columnFilters,

            ImmutableArray<Outputs.GetReportDefinitionColumnInfoResult> columnInfos,

            ImmutableArray<Outputs.GetReportDefinitionColumnSortingResult> columnSortings,

            string compartmentId,

            ImmutableArray<string> complianceStandards,

            string dataSource,

            ImmutableDictionary<string, string> definedTags,

            string description,

            string displayName,

            int displayOrder,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            bool isSeeded,

            string lifecycleDetails,

            string parentId,

            string recordTimeSpan,

            string reportDefinitionId,

            string schedule,

            string scheduledReportCompartmentId,

            string scheduledReportMimeType,

            string scheduledReportName,

            int scheduledReportRowLimit,

            string scimFilter,

            string state,

            ImmutableArray<Outputs.GetReportDefinitionSummaryResult> summaries,

            ImmutableDictionary<string, string> systemTags,

            string timeCreated,

            string timeUpdated)
        {
            Category = category;
            ColumnFilters = columnFilters;
            ColumnInfos = columnInfos;
            ColumnSortings = columnSortings;
            CompartmentId = compartmentId;
            ComplianceStandards = complianceStandards;
            DataSource = dataSource;
            DefinedTags = definedTags;
            Description = description;
            DisplayName = displayName;
            DisplayOrder = displayOrder;
            FreeformTags = freeformTags;
            Id = id;
            IsSeeded = isSeeded;
            LifecycleDetails = lifecycleDetails;
            ParentId = parentId;
            RecordTimeSpan = recordTimeSpan;
            ReportDefinitionId = reportDefinitionId;
            Schedule = schedule;
            ScheduledReportCompartmentId = scheduledReportCompartmentId;
            ScheduledReportMimeType = scheduledReportMimeType;
            ScheduledReportName = scheduledReportName;
            ScheduledReportRowLimit = scheduledReportRowLimit;
            ScimFilter = scimFilter;
            State = state;
            Summaries = summaries;
            SystemTags = systemTags;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
        }
    }
}
