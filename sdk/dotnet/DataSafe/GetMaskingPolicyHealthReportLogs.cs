// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataSafe
{
    public static class GetMaskingPolicyHealthReportLogs
    {
        /// <summary>
        /// This data source provides the list of Masking Policy Health Report Logs in Oracle Cloud Infrastructure Data Safe service.
        /// 
        /// Gets a list of errors and warnings from a masking policy health check.
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
        ///     var testMaskingPolicyHealthReportLogs = Oci.DataSafe.GetMaskingPolicyHealthReportLogs.Invoke(new()
        ///     {
        ///         MaskingPolicyHealthReportId = testMaskingPolicyHealthReport.Id,
        ///         MessageType = maskingPolicyHealthReportLogMessageType,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetMaskingPolicyHealthReportLogsResult> InvokeAsync(GetMaskingPolicyHealthReportLogsArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetMaskingPolicyHealthReportLogsResult>("oci:DataSafe/getMaskingPolicyHealthReportLogs:getMaskingPolicyHealthReportLogs", args ?? new GetMaskingPolicyHealthReportLogsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Masking Policy Health Report Logs in Oracle Cloud Infrastructure Data Safe service.
        /// 
        /// Gets a list of errors and warnings from a masking policy health check.
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
        ///     var testMaskingPolicyHealthReportLogs = Oci.DataSafe.GetMaskingPolicyHealthReportLogs.Invoke(new()
        ///     {
        ///         MaskingPolicyHealthReportId = testMaskingPolicyHealthReport.Id,
        ///         MessageType = maskingPolicyHealthReportLogMessageType,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetMaskingPolicyHealthReportLogsResult> Invoke(GetMaskingPolicyHealthReportLogsInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetMaskingPolicyHealthReportLogsResult>("oci:DataSafe/getMaskingPolicyHealthReportLogs:getMaskingPolicyHealthReportLogs", args ?? new GetMaskingPolicyHealthReportLogsInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Masking Policy Health Report Logs in Oracle Cloud Infrastructure Data Safe service.
        /// 
        /// Gets a list of errors and warnings from a masking policy health check.
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
        ///     var testMaskingPolicyHealthReportLogs = Oci.DataSafe.GetMaskingPolicyHealthReportLogs.Invoke(new()
        ///     {
        ///         MaskingPolicyHealthReportId = testMaskingPolicyHealthReport.Id,
        ///         MessageType = maskingPolicyHealthReportLogMessageType,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetMaskingPolicyHealthReportLogsResult> Invoke(GetMaskingPolicyHealthReportLogsInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetMaskingPolicyHealthReportLogsResult>("oci:DataSafe/getMaskingPolicyHealthReportLogs:getMaskingPolicyHealthReportLogs", args ?? new GetMaskingPolicyHealthReportLogsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetMaskingPolicyHealthReportLogsArgs : global::Pulumi.InvokeArgs
    {
        [Input("filters")]
        private List<Inputs.GetMaskingPolicyHealthReportLogsFilterArgs>? _filters;
        public List<Inputs.GetMaskingPolicyHealthReportLogsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetMaskingPolicyHealthReportLogsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The OCID of the masking health report.
        /// </summary>
        [Input("maskingPolicyHealthReportId", required: true)]
        public string MaskingPolicyHealthReportId { get; set; } = null!;

        /// <summary>
        /// A filter to return only the resources that match the specified log message type.
        /// </summary>
        [Input("messageType")]
        public string? MessageType { get; set; }

        public GetMaskingPolicyHealthReportLogsArgs()
        {
        }
        public static new GetMaskingPolicyHealthReportLogsArgs Empty => new GetMaskingPolicyHealthReportLogsArgs();
    }

    public sealed class GetMaskingPolicyHealthReportLogsInvokeArgs : global::Pulumi.InvokeArgs
    {
        [Input("filters")]
        private InputList<Inputs.GetMaskingPolicyHealthReportLogsFilterInputArgs>? _filters;
        public InputList<Inputs.GetMaskingPolicyHealthReportLogsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetMaskingPolicyHealthReportLogsFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The OCID of the masking health report.
        /// </summary>
        [Input("maskingPolicyHealthReportId", required: true)]
        public Input<string> MaskingPolicyHealthReportId { get; set; } = null!;

        /// <summary>
        /// A filter to return only the resources that match the specified log message type.
        /// </summary>
        [Input("messageType")]
        public Input<string>? MessageType { get; set; }

        public GetMaskingPolicyHealthReportLogsInvokeArgs()
        {
        }
        public static new GetMaskingPolicyHealthReportLogsInvokeArgs Empty => new GetMaskingPolicyHealthReportLogsInvokeArgs();
    }


    [OutputType]
    public sealed class GetMaskingPolicyHealthReportLogsResult
    {
        public readonly ImmutableArray<Outputs.GetMaskingPolicyHealthReportLogsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly string MaskingPolicyHealthReportId;
        /// <summary>
        /// The list of masking_policy_health_report_log_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetMaskingPolicyHealthReportLogsMaskingPolicyHealthReportLogCollectionResult> MaskingPolicyHealthReportLogCollections;
        /// <summary>
        /// The log entry type.
        /// </summary>
        public readonly string? MessageType;

        [OutputConstructor]
        private GetMaskingPolicyHealthReportLogsResult(
            ImmutableArray<Outputs.GetMaskingPolicyHealthReportLogsFilterResult> filters,

            string id,

            string maskingPolicyHealthReportId,

            ImmutableArray<Outputs.GetMaskingPolicyHealthReportLogsMaskingPolicyHealthReportLogCollectionResult> maskingPolicyHealthReportLogCollections,

            string? messageType)
        {
            Filters = filters;
            Id = id;
            MaskingPolicyHealthReportId = maskingPolicyHealthReportId;
            MaskingPolicyHealthReportLogCollections = maskingPolicyHealthReportLogCollections;
            MessageType = messageType;
        }
    }
}
