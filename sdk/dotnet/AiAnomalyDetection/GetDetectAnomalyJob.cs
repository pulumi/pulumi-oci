// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.AiAnomalyDetection
{
    public static class GetDetectAnomalyJob
    {
        /// <summary>
        /// This data source provides details about a specific Detect Anomaly Job resource in Oracle Cloud Infrastructure Ai Anomaly Detection service.
        /// 
        /// Gets a detect anomaly asynchronous job by identifier.
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
        ///     var testDetectAnomalyJob = Oci.AiAnomalyDetection.GetDetectAnomalyJob.Invoke(new()
        ///     {
        ///         DetectAnomalyJobId = oci_ai_anomaly_detection_detect_anomaly_job.Test_detect_anomaly_job.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetDetectAnomalyJobResult> InvokeAsync(GetDetectAnomalyJobArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetDetectAnomalyJobResult>("oci:AiAnomalyDetection/getDetectAnomalyJob:getDetectAnomalyJob", args ?? new GetDetectAnomalyJobArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Detect Anomaly Job resource in Oracle Cloud Infrastructure Ai Anomaly Detection service.
        /// 
        /// Gets a detect anomaly asynchronous job by identifier.
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
        ///     var testDetectAnomalyJob = Oci.AiAnomalyDetection.GetDetectAnomalyJob.Invoke(new()
        ///     {
        ///         DetectAnomalyJobId = oci_ai_anomaly_detection_detect_anomaly_job.Test_detect_anomaly_job.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetDetectAnomalyJobResult> Invoke(GetDetectAnomalyJobInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetDetectAnomalyJobResult>("oci:AiAnomalyDetection/getDetectAnomalyJob:getDetectAnomalyJob", args ?? new GetDetectAnomalyJobInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetDetectAnomalyJobArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// Unique asynchronous job identifier.
        /// </summary>
        [Input("detectAnomalyJobId", required: true)]
        public string DetectAnomalyJobId { get; set; } = null!;

        public GetDetectAnomalyJobArgs()
        {
        }
        public static new GetDetectAnomalyJobArgs Empty => new GetDetectAnomalyJobArgs();
    }

    public sealed class GetDetectAnomalyJobInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// Unique asynchronous job identifier.
        /// </summary>
        [Input("detectAnomalyJobId", required: true)]
        public Input<string> DetectAnomalyJobId { get; set; } = null!;

        public GetDetectAnomalyJobInvokeArgs()
        {
        }
        public static new GetDetectAnomalyJobInvokeArgs Empty => new GetDetectAnomalyJobInvokeArgs();
    }


    [OutputType]
    public sealed class GetDetectAnomalyJobResult
    {
        /// <summary>
        /// The OCID of the compartment that starts the job.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        /// <summary>
        /// Detect anomaly job description.
        /// </summary>
        public readonly string Description;
        public readonly string DetectAnomalyJobId;
        /// <summary>
        /// Detect anomaly job display name.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// Id of the job.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Input details for detect anomaly job.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDetectAnomalyJobInputDetailResult> InputDetails;
        /// <summary>
        /// The current state details of the batch document job.
        /// </summary>
        public readonly string LifecycleStateDetails;
        /// <summary>
        /// The OCID of the trained model.
        /// </summary>
        public readonly string ModelId;
        /// <summary>
        /// Output details for detect anomaly job.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDetectAnomalyJobOutputDetailResult> OutputDetails;
        /// <summary>
        /// The OCID of the project.
        /// </summary>
        public readonly string ProjectId;
        /// <summary>
        /// The value that customer can adjust to control the sensitivity of anomaly detection
        /// </summary>
        public readonly double Sensitivity;
        /// <summary>
        /// The current state of the batch document job.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> SystemTags;
        /// <summary>
        /// Job accepted time
        /// </summary>
        public readonly string TimeAccepted;
        /// <summary>
        /// Job finished time
        /// </summary>
        public readonly string TimeFinished;
        /// <summary>
        /// Job started time
        /// </summary>
        public readonly string TimeStarted;

        [OutputConstructor]
        private GetDetectAnomalyJobResult(
            string compartmentId,

            ImmutableDictionary<string, object> definedTags,

            string description,

            string detectAnomalyJobId,

            string displayName,

            ImmutableDictionary<string, object> freeformTags,

            string id,

            ImmutableArray<Outputs.GetDetectAnomalyJobInputDetailResult> inputDetails,

            string lifecycleStateDetails,

            string modelId,

            ImmutableArray<Outputs.GetDetectAnomalyJobOutputDetailResult> outputDetails,

            string projectId,

            double sensitivity,

            string state,

            ImmutableDictionary<string, object> systemTags,

            string timeAccepted,

            string timeFinished,

            string timeStarted)
        {
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            Description = description;
            DetectAnomalyJobId = detectAnomalyJobId;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            InputDetails = inputDetails;
            LifecycleStateDetails = lifecycleStateDetails;
            ModelId = modelId;
            OutputDetails = outputDetails;
            ProjectId = projectId;
            Sensitivity = sensitivity;
            State = state;
            SystemTags = systemTags;
            TimeAccepted = timeAccepted;
            TimeFinished = timeFinished;
            TimeStarted = timeStarted;
        }
    }
}