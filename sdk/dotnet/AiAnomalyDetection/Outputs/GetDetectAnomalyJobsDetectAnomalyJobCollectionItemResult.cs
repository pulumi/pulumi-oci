// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.AiAnomalyDetection.Outputs
{

    [OutputType]
    public sealed class GetDetectAnomalyJobsDetectAnomalyJobCollectionItemResult
    {
        /// <summary>
        /// The ID of the compartment in which to list resources.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// Detect anomaly job description.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// A filter to return only resources that match the entire display name given.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// Id of the job.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Input details for detect anomaly job.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDetectAnomalyJobsDetectAnomalyJobCollectionItemInputDetailResult> InputDetails;
        /// <summary>
        /// The current state details of the batch document job.
        /// </summary>
        public readonly string LifecycleStateDetails;
        /// <summary>
        /// The ID of the trained model for which to list the resources.
        /// </summary>
        public readonly string ModelId;
        /// <summary>
        /// Output details for detect anomaly job.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDetectAnomalyJobsDetectAnomalyJobCollectionItemOutputDetailResult> OutputDetails;
        /// <summary>
        /// The ID of the project for which to list the objects.
        /// </summary>
        public readonly string ProjectId;
        /// <summary>
        /// The value that customer can adjust to control the sensitivity of anomaly detection
        /// </summary>
        public readonly double Sensitivity;
        /// <summary>
        /// &lt;b&gt;Filter&lt;/b&gt; results by the specified lifecycle state. Must be a valid state for the resource type.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> SystemTags;
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
        private GetDetectAnomalyJobsDetectAnomalyJobCollectionItemResult(
            string compartmentId,

            ImmutableDictionary<string, string> definedTags,

            string description,

            string displayName,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            ImmutableArray<Outputs.GetDetectAnomalyJobsDetectAnomalyJobCollectionItemInputDetailResult> inputDetails,

            string lifecycleStateDetails,

            string modelId,

            ImmutableArray<Outputs.GetDetectAnomalyJobsDetectAnomalyJobCollectionItemOutputDetailResult> outputDetails,

            string projectId,

            double sensitivity,

            string state,

            ImmutableDictionary<string, string> systemTags,

            string timeAccepted,

            string timeFinished,

            string timeStarted)
        {
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            Description = description;
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
