// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.AiAnomalyDetection
{
    /// <summary>
    /// This resource provides the Detect Anomaly Job resource in Oracle Cloud Infrastructure Ai Anomaly Detection service.
    /// 
    /// Creates a job to perform anomaly detection.
    /// 
    /// ## Import
    /// 
    /// DetectAnomalyJobs can be imported using the `id`, e.g.
    /// 
    /// ```sh
    /// $ pulumi import oci:AiAnomalyDetection/detectAnomalyJob:DetectAnomalyJob test_detect_anomaly_job "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:AiAnomalyDetection/detectAnomalyJob:DetectAnomalyJob")]
    public partial class DetectAnomalyJob : global::Pulumi.CustomResource
    {
        /// <summary>
        /// (Updatable) The OCID of the compartment that starts the job.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, string>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) A short description of the detect anomaly job.
        /// </summary>
        [Output("description")]
        public Output<string> Description { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Detect anomaly job display name.
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, string>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// Detect anomaly asynchronous job details.
        /// </summary>
        [Output("inputDetails")]
        public Output<Outputs.DetectAnomalyJobInputDetails> InputDetails { get; private set; } = null!;

        /// <summary>
        /// The current state details of the batch document job.
        /// </summary>
        [Output("lifecycleStateDetails")]
        public Output<string> LifecycleStateDetails { get; private set; } = null!;

        /// <summary>
        /// The OCID of the trained model.
        /// </summary>
        [Output("modelId")]
        public Output<string> ModelId { get; private set; } = null!;

        /// <summary>
        /// Detect anomaly job output details.
        /// </summary>
        [Output("outputDetails")]
        public Output<Outputs.DetectAnomalyJobOutputDetails> OutputDetails { get; private set; } = null!;

        /// <summary>
        /// The OCID of the project.
        /// </summary>
        [Output("projectId")]
        public Output<string> ProjectId { get; private set; } = null!;

        /// <summary>
        /// The value that customer can adjust to control the sensitivity of anomaly detection
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Output("sensitivity")]
        public Output<double> Sensitivity { get; private set; } = null!;

        /// <summary>
        /// The current state of the batch document job.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        [Output("systemTags")]
        public Output<ImmutableDictionary<string, string>> SystemTags { get; private set; } = null!;

        /// <summary>
        /// Job accepted time
        /// </summary>
        [Output("timeAccepted")]
        public Output<string> TimeAccepted { get; private set; } = null!;

        /// <summary>
        /// Job finished time
        /// </summary>
        [Output("timeFinished")]
        public Output<string> TimeFinished { get; private set; } = null!;

        /// <summary>
        /// Job started time
        /// </summary>
        [Output("timeStarted")]
        public Output<string> TimeStarted { get; private set; } = null!;


        /// <summary>
        /// Create a DetectAnomalyJob resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public DetectAnomalyJob(string name, DetectAnomalyJobArgs args, CustomResourceOptions? options = null)
            : base("oci:AiAnomalyDetection/detectAnomalyJob:DetectAnomalyJob", name, args ?? new DetectAnomalyJobArgs(), MakeResourceOptions(options, ""))
        {
        }

        private DetectAnomalyJob(string name, Input<string> id, DetectAnomalyJobState? state = null, CustomResourceOptions? options = null)
            : base("oci:AiAnomalyDetection/detectAnomalyJob:DetectAnomalyJob", name, state, MakeResourceOptions(options, id))
        {
        }

        private static CustomResourceOptions MakeResourceOptions(CustomResourceOptions? options, Input<string>? id)
        {
            var defaultOptions = new CustomResourceOptions
            {
                Version = Utilities.Version,
            };
            var merged = CustomResourceOptions.Merge(defaultOptions, options);
            // Override the ID if one was specified for consistency with other language SDKs.
            merged.Id = id ?? merged.Id;
            return merged;
        }
        /// <summary>
        /// Get an existing DetectAnomalyJob resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static DetectAnomalyJob Get(string name, Input<string> id, DetectAnomalyJobState? state = null, CustomResourceOptions? options = null)
        {
            return new DetectAnomalyJob(name, id, state, options);
        }
    }

    public sealed class DetectAnomalyJobArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The OCID of the compartment that starts the job.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// (Updatable) A short description of the detect anomaly job.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// (Updatable) Detect anomaly job display name.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        /// <summary>
        /// Detect anomaly asynchronous job details.
        /// </summary>
        [Input("inputDetails", required: true)]
        public Input<Inputs.DetectAnomalyJobInputDetailsArgs> InputDetails { get; set; } = null!;

        /// <summary>
        /// The OCID of the trained model.
        /// </summary>
        [Input("modelId", required: true)]
        public Input<string> ModelId { get; set; } = null!;

        /// <summary>
        /// Detect anomaly job output details.
        /// </summary>
        [Input("outputDetails", required: true)]
        public Input<Inputs.DetectAnomalyJobOutputDetailsArgs> OutputDetails { get; set; } = null!;

        /// <summary>
        /// The value that customer can adjust to control the sensitivity of anomaly detection
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("sensitivity")]
        public Input<double>? Sensitivity { get; set; }

        public DetectAnomalyJobArgs()
        {
        }
        public static new DetectAnomalyJobArgs Empty => new DetectAnomalyJobArgs();
    }

    public sealed class DetectAnomalyJobState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The OCID of the compartment that starts the job.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        [Input("definedTags")]
        private InputMap<string>? _definedTags;

        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public InputMap<string> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<string>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) A short description of the detect anomaly job.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// (Updatable) Detect anomaly job display name.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("freeformTags")]
        private InputMap<string>? _freeformTags;

        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public InputMap<string> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<string>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// Detect anomaly asynchronous job details.
        /// </summary>
        [Input("inputDetails")]
        public Input<Inputs.DetectAnomalyJobInputDetailsGetArgs>? InputDetails { get; set; }

        /// <summary>
        /// The current state details of the batch document job.
        /// </summary>
        [Input("lifecycleStateDetails")]
        public Input<string>? LifecycleStateDetails { get; set; }

        /// <summary>
        /// The OCID of the trained model.
        /// </summary>
        [Input("modelId")]
        public Input<string>? ModelId { get; set; }

        /// <summary>
        /// Detect anomaly job output details.
        /// </summary>
        [Input("outputDetails")]
        public Input<Inputs.DetectAnomalyJobOutputDetailsGetArgs>? OutputDetails { get; set; }

        /// <summary>
        /// The OCID of the project.
        /// </summary>
        [Input("projectId")]
        public Input<string>? ProjectId { get; set; }

        /// <summary>
        /// The value that customer can adjust to control the sensitivity of anomaly detection
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("sensitivity")]
        public Input<double>? Sensitivity { get; set; }

        /// <summary>
        /// The current state of the batch document job.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        [Input("systemTags")]
        private InputMap<string>? _systemTags;

        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public InputMap<string> SystemTags
        {
            get => _systemTags ?? (_systemTags = new InputMap<string>());
            set => _systemTags = value;
        }

        /// <summary>
        /// Job accepted time
        /// </summary>
        [Input("timeAccepted")]
        public Input<string>? TimeAccepted { get; set; }

        /// <summary>
        /// Job finished time
        /// </summary>
        [Input("timeFinished")]
        public Input<string>? TimeFinished { get; set; }

        /// <summary>
        /// Job started time
        /// </summary>
        [Input("timeStarted")]
        public Input<string>? TimeStarted { get; set; }

        public DetectAnomalyJobState()
        {
        }
        public static new DetectAnomalyJobState Empty => new DetectAnomalyJobState();
    }
}
