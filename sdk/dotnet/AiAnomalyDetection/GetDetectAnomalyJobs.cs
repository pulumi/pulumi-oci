// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.AiAnomalyDetection
{
    public static class GetDetectAnomalyJobs
    {
        /// <summary>
        /// This data source provides the list of Detect Anomaly Jobs in Oracle Cloud Infrastructure Ai Anomaly Detection service.
        /// 
        /// Returns a list of all the Anomaly Detection jobs in the specified compartment.
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
        ///     var testDetectAnomalyJobs = Oci.AiAnomalyDetection.GetDetectAnomalyJobs.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         DetectAnomalyJobId = testDetectAnomalyJob.Id,
        ///         DisplayName = detectAnomalyJobDisplayName,
        ///         ModelId = testModel.Id,
        ///         ProjectId = testProject.Id,
        ///         State = detectAnomalyJobState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetDetectAnomalyJobsResult> InvokeAsync(GetDetectAnomalyJobsArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetDetectAnomalyJobsResult>("oci:AiAnomalyDetection/getDetectAnomalyJobs:getDetectAnomalyJobs", args ?? new GetDetectAnomalyJobsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Detect Anomaly Jobs in Oracle Cloud Infrastructure Ai Anomaly Detection service.
        /// 
        /// Returns a list of all the Anomaly Detection jobs in the specified compartment.
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
        ///     var testDetectAnomalyJobs = Oci.AiAnomalyDetection.GetDetectAnomalyJobs.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         DetectAnomalyJobId = testDetectAnomalyJob.Id,
        ///         DisplayName = detectAnomalyJobDisplayName,
        ///         ModelId = testModel.Id,
        ///         ProjectId = testProject.Id,
        ///         State = detectAnomalyJobState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetDetectAnomalyJobsResult> Invoke(GetDetectAnomalyJobsInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetDetectAnomalyJobsResult>("oci:AiAnomalyDetection/getDetectAnomalyJobs:getDetectAnomalyJobs", args ?? new GetDetectAnomalyJobsInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Detect Anomaly Jobs in Oracle Cloud Infrastructure Ai Anomaly Detection service.
        /// 
        /// Returns a list of all the Anomaly Detection jobs in the specified compartment.
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
        ///     var testDetectAnomalyJobs = Oci.AiAnomalyDetection.GetDetectAnomalyJobs.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         DetectAnomalyJobId = testDetectAnomalyJob.Id,
        ///         DisplayName = detectAnomalyJobDisplayName,
        ///         ModelId = testModel.Id,
        ///         ProjectId = testProject.Id,
        ///         State = detectAnomalyJobState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetDetectAnomalyJobsResult> Invoke(GetDetectAnomalyJobsInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetDetectAnomalyJobsResult>("oci:AiAnomalyDetection/getDetectAnomalyJobs:getDetectAnomalyJobs", args ?? new GetDetectAnomalyJobsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetDetectAnomalyJobsArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The ID of the compartment in which to list resources.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// Unique Async Job identifier
        /// </summary>
        [Input("detectAnomalyJobId")]
        public string? DetectAnomalyJobId { get; set; }

        /// <summary>
        /// A filter to return only resources that match the entire display name given.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetDetectAnomalyJobsFilterArgs>? _filters;
        public List<Inputs.GetDetectAnomalyJobsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetDetectAnomalyJobsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The ID of the trained model for which to list the resources.
        /// </summary>
        [Input("modelId")]
        public string? ModelId { get; set; }

        /// <summary>
        /// The ID of the project for which to list the objects.
        /// </summary>
        [Input("projectId")]
        public string? ProjectId { get; set; }

        /// <summary>
        /// &lt;b&gt;Filter&lt;/b&gt; results by the specified lifecycle state. Must be a valid state for the resource type.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        public GetDetectAnomalyJobsArgs()
        {
        }
        public static new GetDetectAnomalyJobsArgs Empty => new GetDetectAnomalyJobsArgs();
    }

    public sealed class GetDetectAnomalyJobsInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The ID of the compartment in which to list resources.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// Unique Async Job identifier
        /// </summary>
        [Input("detectAnomalyJobId")]
        public Input<string>? DetectAnomalyJobId { get; set; }

        /// <summary>
        /// A filter to return only resources that match the entire display name given.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetDetectAnomalyJobsFilterInputArgs>? _filters;
        public InputList<Inputs.GetDetectAnomalyJobsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetDetectAnomalyJobsFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The ID of the trained model for which to list the resources.
        /// </summary>
        [Input("modelId")]
        public Input<string>? ModelId { get; set; }

        /// <summary>
        /// The ID of the project for which to list the objects.
        /// </summary>
        [Input("projectId")]
        public Input<string>? ProjectId { get; set; }

        /// <summary>
        /// &lt;b&gt;Filter&lt;/b&gt; results by the specified lifecycle state. Must be a valid state for the resource type.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        public GetDetectAnomalyJobsInvokeArgs()
        {
        }
        public static new GetDetectAnomalyJobsInvokeArgs Empty => new GetDetectAnomalyJobsInvokeArgs();
    }


    [OutputType]
    public sealed class GetDetectAnomalyJobsResult
    {
        /// <summary>
        /// The OCID of the compartment that starts the job.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The list of detect_anomaly_job_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDetectAnomalyJobsDetectAnomalyJobCollectionResult> DetectAnomalyJobCollections;
        public readonly string? DetectAnomalyJobId;
        /// <summary>
        /// Detect anomaly job display name.
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetDetectAnomalyJobsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The OCID of the trained model.
        /// </summary>
        public readonly string? ModelId;
        /// <summary>
        /// The OCID of the project.
        /// </summary>
        public readonly string? ProjectId;
        /// <summary>
        /// The current state of the batch document job.
        /// </summary>
        public readonly string? State;

        [OutputConstructor]
        private GetDetectAnomalyJobsResult(
            string compartmentId,

            ImmutableArray<Outputs.GetDetectAnomalyJobsDetectAnomalyJobCollectionResult> detectAnomalyJobCollections,

            string? detectAnomalyJobId,

            string? displayName,

            ImmutableArray<Outputs.GetDetectAnomalyJobsFilterResult> filters,

            string id,

            string? modelId,

            string? projectId,

            string? state)
        {
            CompartmentId = compartmentId;
            DetectAnomalyJobCollections = detectAnomalyJobCollections;
            DetectAnomalyJobId = detectAnomalyJobId;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            ModelId = modelId;
            ProjectId = projectId;
            State = state;
        }
    }
}
