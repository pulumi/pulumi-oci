// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.StackMonitoring
{
    public static class GetDiscoveryJobLogs
    {
        /// <summary>
        /// This data source provides the list of Discovery Job Logs in Oracle Cloud Infrastructure Stack Monitoring service.
        /// 
        /// API to get all the logs of a Discovery Job.
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
        ///     var testDiscoveryJobLogs = Oci.StackMonitoring.GetDiscoveryJobLogs.Invoke(new()
        ///     {
        ///         DiscoveryJobId = testDiscoveryJob.Id,
        ///         LogType = discoveryJobLogLogType,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetDiscoveryJobLogsResult> InvokeAsync(GetDiscoveryJobLogsArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetDiscoveryJobLogsResult>("oci:StackMonitoring/getDiscoveryJobLogs:getDiscoveryJobLogs", args ?? new GetDiscoveryJobLogsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Discovery Job Logs in Oracle Cloud Infrastructure Stack Monitoring service.
        /// 
        /// API to get all the logs of a Discovery Job.
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
        ///     var testDiscoveryJobLogs = Oci.StackMonitoring.GetDiscoveryJobLogs.Invoke(new()
        ///     {
        ///         DiscoveryJobId = testDiscoveryJob.Id,
        ///         LogType = discoveryJobLogLogType,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetDiscoveryJobLogsResult> Invoke(GetDiscoveryJobLogsInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetDiscoveryJobLogsResult>("oci:StackMonitoring/getDiscoveryJobLogs:getDiscoveryJobLogs", args ?? new GetDiscoveryJobLogsInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Discovery Job Logs in Oracle Cloud Infrastructure Stack Monitoring service.
        /// 
        /// API to get all the logs of a Discovery Job.
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
        ///     var testDiscoveryJobLogs = Oci.StackMonitoring.GetDiscoveryJobLogs.Invoke(new()
        ///     {
        ///         DiscoveryJobId = testDiscoveryJob.Id,
        ///         LogType = discoveryJobLogLogType,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetDiscoveryJobLogsResult> Invoke(GetDiscoveryJobLogsInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetDiscoveryJobLogsResult>("oci:StackMonitoring/getDiscoveryJobLogs:getDiscoveryJobLogs", args ?? new GetDiscoveryJobLogsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetDiscoveryJobLogsArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The Discovery Job ID
        /// </summary>
        [Input("discoveryJobId", required: true)]
        public string DiscoveryJobId { get; set; } = null!;

        [Input("filters")]
        private List<Inputs.GetDiscoveryJobLogsFilterArgs>? _filters;
        public List<Inputs.GetDiscoveryJobLogsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetDiscoveryJobLogsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The log type like INFO, WARNING, ERROR, SUCCESS
        /// </summary>
        [Input("logType")]
        public string? LogType { get; set; }

        public GetDiscoveryJobLogsArgs()
        {
        }
        public static new GetDiscoveryJobLogsArgs Empty => new GetDiscoveryJobLogsArgs();
    }

    public sealed class GetDiscoveryJobLogsInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The Discovery Job ID
        /// </summary>
        [Input("discoveryJobId", required: true)]
        public Input<string> DiscoveryJobId { get; set; } = null!;

        [Input("filters")]
        private InputList<Inputs.GetDiscoveryJobLogsFilterInputArgs>? _filters;
        public InputList<Inputs.GetDiscoveryJobLogsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetDiscoveryJobLogsFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The log type like INFO, WARNING, ERROR, SUCCESS
        /// </summary>
        [Input("logType")]
        public Input<string>? LogType { get; set; }

        public GetDiscoveryJobLogsInvokeArgs()
        {
        }
        public static new GetDiscoveryJobLogsInvokeArgs Empty => new GetDiscoveryJobLogsInvokeArgs();
    }


    [OutputType]
    public sealed class GetDiscoveryJobLogsResult
    {
        public readonly string DiscoveryJobId;
        /// <summary>
        /// The list of discovery_job_log_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDiscoveryJobLogsDiscoveryJobLogCollectionResult> DiscoveryJobLogCollections;
        public readonly ImmutableArray<Outputs.GetDiscoveryJobLogsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Type of log (INFO, WARNING, ERROR or SUCCESS)
        /// </summary>
        public readonly string? LogType;

        [OutputConstructor]
        private GetDiscoveryJobLogsResult(
            string discoveryJobId,

            ImmutableArray<Outputs.GetDiscoveryJobLogsDiscoveryJobLogCollectionResult> discoveryJobLogCollections,

            ImmutableArray<Outputs.GetDiscoveryJobLogsFilterResult> filters,

            string id,

            string? logType)
        {
            DiscoveryJobId = discoveryJobId;
            DiscoveryJobLogCollections = discoveryJobLogCollections;
            Filters = filters;
            Id = id;
            LogType = logType;
        }
    }
}
