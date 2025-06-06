// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataSafe
{
    public static class GetReport
    {
        /// <summary>
        /// This data source provides details about a specific Report resource in Oracle Cloud Infrastructure Data Safe service.
        /// 
        /// Gets a report by identifier
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
        ///     var testReport = Oci.DataSafe.GetReport.Invoke(new()
        ///     {
        ///         ReportId = testReportOciDataSafeReport.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetReportResult> InvokeAsync(GetReportArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetReportResult>("oci:DataSafe/getReport:getReport", args ?? new GetReportArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Report resource in Oracle Cloud Infrastructure Data Safe service.
        /// 
        /// Gets a report by identifier
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
        ///     var testReport = Oci.DataSafe.GetReport.Invoke(new()
        ///     {
        ///         ReportId = testReportOciDataSafeReport.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetReportResult> Invoke(GetReportInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetReportResult>("oci:DataSafe/getReport:getReport", args ?? new GetReportInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Report resource in Oracle Cloud Infrastructure Data Safe service.
        /// 
        /// Gets a report by identifier
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
        ///     var testReport = Oci.DataSafe.GetReport.Invoke(new()
        ///     {
        ///         ReportId = testReportOciDataSafeReport.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetReportResult> Invoke(GetReportInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetReportResult>("oci:DataSafe/getReport:getReport", args ?? new GetReportInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetReportArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// Unique report identifier
        /// </summary>
        [Input("reportId", required: true)]
        public string ReportId { get; set; } = null!;

        public GetReportArgs()
        {
        }
        public static new GetReportArgs Empty => new GetReportArgs();
    }

    public sealed class GetReportInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// Unique report identifier
        /// </summary>
        [Input("reportId", required: true)]
        public Input<string> ReportId { get; set; } = null!;

        public GetReportInvokeArgs()
        {
        }
        public static new GetReportInvokeArgs Empty => new GetReportInvokeArgs();
    }


    [OutputType]
    public sealed class GetReportResult
    {
        /// <summary>
        /// The OCID of the compartment containing the report.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm) Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// Specifies a description of the report.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// Name of the report.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// The OCID of the report.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Details about the current state of the report in Data Safe.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// Specifies the format of report to be .xls or .pdf or .json
        /// </summary>
        public readonly string MimeType;
        /// <summary>
        /// The OCID of the report definition.
        /// </summary>
        public readonly string ReportDefinitionId;
        public readonly string ReportId;
        /// <summary>
        /// The current state of the audit report.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> SystemTags;
        /// <summary>
        /// Specifies the date and time the report was generated.
        /// </summary>
        public readonly string TimeGenerated;
        /// <summary>
        /// The type of the audit report.
        /// </summary>
        public readonly string Type;

        [OutputConstructor]
        private GetReportResult(
            string compartmentId,

            ImmutableDictionary<string, string> definedTags,

            string description,

            string displayName,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            string lifecycleDetails,

            string mimeType,

            string reportDefinitionId,

            string reportId,

            string state,

            ImmutableDictionary<string, string> systemTags,

            string timeGenerated,

            string type)
        {
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            Description = description;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            LifecycleDetails = lifecycleDetails;
            MimeType = mimeType;
            ReportDefinitionId = reportDefinitionId;
            ReportId = reportId;
            State = state;
            SystemTags = systemTags;
            TimeGenerated = timeGenerated;
            Type = type;
        }
    }
}
