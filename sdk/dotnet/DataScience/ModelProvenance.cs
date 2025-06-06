// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataScience
{
    /// <summary>
    /// This resource provides the Model Provenance resource in Oracle Cloud Infrastructure Data Science service.
    /// 
    /// Creates provenance information for the specified model.
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
    ///     var testModelProvenance = new Oci.DataScience.ModelProvenance("test_model_provenance", new()
    ///     {
    ///         ModelId = testModel.Id,
    ///         GitBranch = modelProvenanceGitBranch,
    ///         GitCommit = modelProvenanceGitCommit,
    ///         RepositoryUrl = modelProvenanceRepositoryUrl,
    ///         ScriptDir = modelProvenanceScriptDir,
    ///         TrainingId = testTraining.Id,
    ///         TrainingScript = modelProvenanceTrainingScript,
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// ModelProvenances can be imported using the `id`, e.g.
    /// 
    /// ```sh
    /// $ pulumi import oci:DataScience/modelProvenance:ModelProvenance test_model_provenance "models/{modelId}/provenance"
    /// ```
    /// </summary>
    [OciResourceType("oci:DataScience/modelProvenance:ModelProvenance")]
    public partial class ModelProvenance : global::Pulumi.CustomResource
    {
        /// <summary>
        /// (Updatable) For model reproducibility purposes. Branch of the git repository associated with model training.
        /// </summary>
        [Output("gitBranch")]
        public Output<string> GitBranch { get; private set; } = null!;

        /// <summary>
        /// (Updatable) For model reproducibility purposes. Commit ID of the git repository associated with model training.
        /// </summary>
        [Output("gitCommit")]
        public Output<string> GitCommit { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the model.
        /// </summary>
        [Output("modelId")]
        public Output<string> ModelId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) For model reproducibility purposes. URL of the git repository associated with model training.
        /// </summary>
        [Output("repositoryUrl")]
        public Output<string> RepositoryUrl { get; private set; } = null!;

        /// <summary>
        /// (Updatable) For model reproducibility purposes. Path to model artifacts.
        /// </summary>
        [Output("scriptDir")]
        public Output<string> ScriptDir { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a training session(Job or NotebookSession) in which the model was trained. It is used for model reproducibility purposes.
        /// </summary>
        [Output("trainingId")]
        public Output<string> TrainingId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) For model reproducibility purposes. Path to the python script or notebook in which the model was trained." 
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Output("trainingScript")]
        public Output<string> TrainingScript { get; private set; } = null!;


        /// <summary>
        /// Create a ModelProvenance resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public ModelProvenance(string name, ModelProvenanceArgs args, CustomResourceOptions? options = null)
            : base("oci:DataScience/modelProvenance:ModelProvenance", name, args ?? new ModelProvenanceArgs(), MakeResourceOptions(options, ""))
        {
        }

        private ModelProvenance(string name, Input<string> id, ModelProvenanceState? state = null, CustomResourceOptions? options = null)
            : base("oci:DataScience/modelProvenance:ModelProvenance", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing ModelProvenance resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static ModelProvenance Get(string name, Input<string> id, ModelProvenanceState? state = null, CustomResourceOptions? options = null)
        {
            return new ModelProvenance(name, id, state, options);
        }
    }

    public sealed class ModelProvenanceArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) For model reproducibility purposes. Branch of the git repository associated with model training.
        /// </summary>
        [Input("gitBranch")]
        public Input<string>? GitBranch { get; set; }

        /// <summary>
        /// (Updatable) For model reproducibility purposes. Commit ID of the git repository associated with model training.
        /// </summary>
        [Input("gitCommit")]
        public Input<string>? GitCommit { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the model.
        /// </summary>
        [Input("modelId", required: true)]
        public Input<string> ModelId { get; set; } = null!;

        /// <summary>
        /// (Updatable) For model reproducibility purposes. URL of the git repository associated with model training.
        /// </summary>
        [Input("repositoryUrl")]
        public Input<string>? RepositoryUrl { get; set; }

        /// <summary>
        /// (Updatable) For model reproducibility purposes. Path to model artifacts.
        /// </summary>
        [Input("scriptDir")]
        public Input<string>? ScriptDir { get; set; }

        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a training session(Job or NotebookSession) in which the model was trained. It is used for model reproducibility purposes.
        /// </summary>
        [Input("trainingId")]
        public Input<string>? TrainingId { get; set; }

        /// <summary>
        /// (Updatable) For model reproducibility purposes. Path to the python script or notebook in which the model was trained." 
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("trainingScript")]
        public Input<string>? TrainingScript { get; set; }

        public ModelProvenanceArgs()
        {
        }
        public static new ModelProvenanceArgs Empty => new ModelProvenanceArgs();
    }

    public sealed class ModelProvenanceState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) For model reproducibility purposes. Branch of the git repository associated with model training.
        /// </summary>
        [Input("gitBranch")]
        public Input<string>? GitBranch { get; set; }

        /// <summary>
        /// (Updatable) For model reproducibility purposes. Commit ID of the git repository associated with model training.
        /// </summary>
        [Input("gitCommit")]
        public Input<string>? GitCommit { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the model.
        /// </summary>
        [Input("modelId")]
        public Input<string>? ModelId { get; set; }

        /// <summary>
        /// (Updatable) For model reproducibility purposes. URL of the git repository associated with model training.
        /// </summary>
        [Input("repositoryUrl")]
        public Input<string>? RepositoryUrl { get; set; }

        /// <summary>
        /// (Updatable) For model reproducibility purposes. Path to model artifacts.
        /// </summary>
        [Input("scriptDir")]
        public Input<string>? ScriptDir { get; set; }

        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a training session(Job or NotebookSession) in which the model was trained. It is used for model reproducibility purposes.
        /// </summary>
        [Input("trainingId")]
        public Input<string>? TrainingId { get; set; }

        /// <summary>
        /// (Updatable) For model reproducibility purposes. Path to the python script or notebook in which the model was trained." 
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("trainingScript")]
        public Input<string>? TrainingScript { get; set; }

        public ModelProvenanceState()
        {
        }
        public static new ModelProvenanceState Empty => new ModelProvenanceState();
    }
}
