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
    /// This resource provides the Model resource in Oracle Cloud Infrastructure Ai Anomaly Detection service.
    /// 
    /// Creates a new Model.
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
    ///     var testModel = new Oci.AiAnomalyDetection.Model("test_model", new()
    ///     {
    ///         CompartmentId = compartmentId,
    ///         ModelTrainingDetails = new Oci.AiAnomalyDetection.Inputs.ModelModelTrainingDetailsArgs
    ///         {
    ///             DataAssetIds = modelModelTrainingDetailsDataAssetIds,
    ///             AlgorithmHint = modelModelTrainingDetailsAlgorithmHint,
    ///             TargetFap = modelModelTrainingDetailsTargetFap,
    ///             TrainingFraction = modelModelTrainingDetailsTrainingFraction,
    ///             WindowSize = modelModelTrainingDetailsWindowSize,
    ///         },
    ///         ProjectId = testProject.Id,
    ///         DefinedTags = 
    ///         {
    ///             { "foo-namespace.bar-key", "value" },
    ///         },
    ///         Description = modelDescription,
    ///         DisplayName = modelDisplayName,
    ///         FreeformTags = 
    ///         {
    ///             { "bar-key", "value" },
    ///         },
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// Models can be imported using the `id`, e.g.
    /// 
    /// ```sh
    /// $ pulumi import oci:AiAnomalyDetection/model:Model test_model "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:AiAnomalyDetection/model:Model")]
    public partial class Model : global::Pulumi.CustomResource
    {
        /// <summary>
        /// (Updatable) The OCID for the ai model's compartment.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, string>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) A short description of the ai model.
        /// </summary>
        [Output("description")]
        public Output<string> Description { get; private set; } = null!;

        /// <summary>
        /// (Updatable) A user-friendly display name for the resource. It does not have to be unique and can be modified. Avoid entering confidential information.
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, string>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        [Output("lifecycleDetails")]
        public Output<string> LifecycleDetails { get; private set; } = null!;

        /// <summary>
        /// Specifies the details of the MSET model during the create call.
        /// </summary>
        [Output("modelTrainingDetails")]
        public Output<Outputs.ModelModelTrainingDetails> ModelTrainingDetails { get; private set; } = null!;

        /// <summary>
        /// Specifies the details for an Anomaly Detection model trained with MSET.
        /// </summary>
        [Output("modelTrainingResults")]
        public Output<ImmutableArray<Outputs.ModelModelTrainingResult>> ModelTrainingResults { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate with the model.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Output("projectId")]
        public Output<string> ProjectId { get; private set; } = null!;

        /// <summary>
        /// The state of the model.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        [Output("systemTags")]
        public Output<ImmutableDictionary<string, string>> SystemTags { get; private set; } = null!;

        /// <summary>
        /// The time the the Model was created. An RFC3339 formatted datetime string.
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// The time the Model was updated. An RFC3339 formatted datetime string.
        /// </summary>
        [Output("timeUpdated")]
        public Output<string> TimeUpdated { get; private set; } = null!;


        /// <summary>
        /// Create a Model resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public Model(string name, ModelArgs args, CustomResourceOptions? options = null)
            : base("oci:AiAnomalyDetection/model:Model", name, args ?? new ModelArgs(), MakeResourceOptions(options, ""))
        {
        }

        private Model(string name, Input<string> id, ModelState? state = null, CustomResourceOptions? options = null)
            : base("oci:AiAnomalyDetection/model:Model", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing Model resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static Model Get(string name, Input<string> id, ModelState? state = null, CustomResourceOptions? options = null)
        {
            return new Model(name, id, state, options);
        }
    }

    public sealed class ModelArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The OCID for the ai model's compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        [Input("definedTags")]
        private InputMap<string>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public InputMap<string> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<string>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) A short description of the ai model.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// (Updatable) A user-friendly display name for the resource. It does not have to be unique and can be modified. Avoid entering confidential information.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("freeformTags")]
        private InputMap<string>? _freeformTags;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public InputMap<string> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<string>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// Specifies the details of the MSET model during the create call.
        /// </summary>
        [Input("modelTrainingDetails", required: true)]
        public Input<Inputs.ModelModelTrainingDetailsArgs> ModelTrainingDetails { get; set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate with the model.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("projectId", required: true)]
        public Input<string> ProjectId { get; set; } = null!;

        public ModelArgs()
        {
        }
        public static new ModelArgs Empty => new ModelArgs();
    }

    public sealed class ModelState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The OCID for the ai model's compartment.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        [Input("definedTags")]
        private InputMap<string>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public InputMap<string> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<string>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) A short description of the ai model.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// (Updatable) A user-friendly display name for the resource. It does not have to be unique and can be modified. Avoid entering confidential information.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("freeformTags")]
        private InputMap<string>? _freeformTags;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public InputMap<string> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<string>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        [Input("lifecycleDetails")]
        public Input<string>? LifecycleDetails { get; set; }

        /// <summary>
        /// Specifies the details of the MSET model during the create call.
        /// </summary>
        [Input("modelTrainingDetails")]
        public Input<Inputs.ModelModelTrainingDetailsGetArgs>? ModelTrainingDetails { get; set; }

        [Input("modelTrainingResults")]
        private InputList<Inputs.ModelModelTrainingResultGetArgs>? _modelTrainingResults;

        /// <summary>
        /// Specifies the details for an Anomaly Detection model trained with MSET.
        /// </summary>
        public InputList<Inputs.ModelModelTrainingResultGetArgs> ModelTrainingResults
        {
            get => _modelTrainingResults ?? (_modelTrainingResults = new InputList<Inputs.ModelModelTrainingResultGetArgs>());
            set => _modelTrainingResults = value;
        }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate with the model.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("projectId")]
        public Input<string>? ProjectId { get; set; }

        /// <summary>
        /// The state of the model.
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
        /// The time the the Model was created. An RFC3339 formatted datetime string.
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// The time the Model was updated. An RFC3339 formatted datetime string.
        /// </summary>
        [Input("timeUpdated")]
        public Input<string>? TimeUpdated { get; set; }

        public ModelState()
        {
        }
        public static new ModelState Empty => new ModelState();
    }
}
