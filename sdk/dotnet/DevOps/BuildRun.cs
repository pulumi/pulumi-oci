// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DevOps
{
    /// <summary>
    /// This resource provides the Build Run resource in Oracle Cloud Infrastructure Devops service.
    /// 
    /// Starts a build pipeline run for a predefined build pipeline.
    /// 
    /// ## Example Usage
    /// 
    /// ```csharp
    /// using System.Collections.Generic;
    /// using Pulumi;
    /// using Oci = Pulumi.Oci;
    /// 
    /// return await Deployment.RunAsync(() =&gt; 
    /// {
    ///     var testBuildRun = new Oci.DevOps.BuildRun("testBuildRun", new()
    ///     {
    ///         BuildPipelineId = oci_devops_build_pipeline.Test_build_pipeline.Id,
    ///         BuildRunArguments = new Oci.DevOps.Inputs.BuildRunBuildRunArgumentsArgs
    ///         {
    ///             Items = new[]
    ///             {
    ///                 new Oci.DevOps.Inputs.BuildRunBuildRunArgumentsItemArgs
    ///                 {
    ///                     Name = @var.Build_run_build_run_arguments_items_name,
    ///                     Value = @var.Build_run_build_run_arguments_items_value,
    ///                 },
    ///             },
    ///         },
    ///         CommitInfo = new Oci.DevOps.Inputs.BuildRunCommitInfoArgs
    ///         {
    ///             CommitHash = @var.Build_run_commit_info_commit_hash,
    ///             RepositoryBranch = @var.Build_run_commit_info_repository_branch,
    ///             RepositoryUrl = @var.Build_run_commit_info_repository_url,
    ///         },
    ///         DefinedTags = 
    ///         {
    ///             { "foo-namespace.bar-key", "value" },
    ///         },
    ///         DisplayName = @var.Build_run_display_name,
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
    /// BuildRuns can be imported using the `id`, e.g.
    /// 
    /// ```sh
    ///  $ pulumi import oci:DevOps/buildRun:BuildRun test_build_run "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:DevOps/buildRun:BuildRun")]
    public partial class BuildRun : global::Pulumi.CustomResource
    {
        /// <summary>
        /// Outputs from the build.
        /// </summary>
        [Output("buildOutputs")]
        public Output<ImmutableArray<Outputs.BuildRunBuildOutput>> BuildOutputs { get; private set; } = null!;

        /// <summary>
        /// The OCID of the build pipeline.
        /// </summary>
        [Output("buildPipelineId")]
        public Output<string> BuildPipelineId { get; private set; } = null!;

        /// <summary>
        /// Specifies list of arguments passed along with the build run.
        /// </summary>
        [Output("buildRunArguments")]
        public Output<Outputs.BuildRunBuildRunArguments> BuildRunArguments { get; private set; } = null!;

        /// <summary>
        /// The run progress details of a build run.
        /// </summary>
        [Output("buildRunProgresses")]
        public Output<ImmutableArray<Outputs.BuildRunBuildRunProgress>> BuildRunProgresses { get; private set; } = null!;

        /// <summary>
        /// The source from which the build run is triggered.
        /// </summary>
        [Output("buildRunSources")]
        public Output<ImmutableArray<Outputs.BuildRunBuildRunSource>> BuildRunSources { get; private set; } = null!;

        /// <summary>
        /// Commit details that need to be used for the build run.
        /// </summary>
        [Output("commitInfo")]
        public Output<Outputs.BuildRunCommitInfo> CommitInfo { get; private set; } = null!;

        /// <summary>
        /// The OCID of the compartment where the build is running.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, object>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Build run display name, which can be renamed and is not necessarily unique. Avoid entering confidential information.
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, object>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        [Output("lifecycleDetails")]
        public Output<string> LifecycleDetails { get; private set; } = null!;

        /// <summary>
        /// The OCID of the DevOps project.
        /// </summary>
        [Output("projectId")]
        public Output<string> ProjectId { get; private set; } = null!;

        /// <summary>
        /// The current state of the build run.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        [Output("systemTags")]
        public Output<ImmutableDictionary<string, object>> SystemTags { get; private set; } = null!;

        /// <summary>
        /// The time the build run was created. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// The time the build run was updated. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
        /// </summary>
        [Output("timeUpdated")]
        public Output<string> TimeUpdated { get; private set; } = null!;


        /// <summary>
        /// Create a BuildRun resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public BuildRun(string name, BuildRunArgs args, CustomResourceOptions? options = null)
            : base("oci:DevOps/buildRun:BuildRun", name, args ?? new BuildRunArgs(), MakeResourceOptions(options, ""))
        {
        }

        private BuildRun(string name, Input<string> id, BuildRunState? state = null, CustomResourceOptions? options = null)
            : base("oci:DevOps/buildRun:BuildRun", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing BuildRun resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static BuildRun Get(string name, Input<string> id, BuildRunState? state = null, CustomResourceOptions? options = null)
        {
            return new BuildRun(name, id, state, options);
        }
    }

    public sealed class BuildRunArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The OCID of the build pipeline.
        /// </summary>
        [Input("buildPipelineId", required: true)]
        public Input<string> BuildPipelineId { get; set; } = null!;

        /// <summary>
        /// Specifies list of arguments passed along with the build run.
        /// </summary>
        [Input("buildRunArguments")]
        public Input<Inputs.BuildRunBuildRunArgumentsArgs>? BuildRunArguments { get; set; }

        /// <summary>
        /// Commit details that need to be used for the build run.
        /// </summary>
        [Input("commitInfo")]
        public Input<Inputs.BuildRunCommitInfoArgs>? CommitInfo { get; set; }

        [Input("definedTags")]
        private InputMap<object>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public InputMap<object> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<object>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) Build run display name, which can be renamed and is not necessarily unique. Avoid entering confidential information.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("freeformTags")]
        private InputMap<object>? _freeformTags;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
        /// </summary>
        public InputMap<object> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<object>());
            set => _freeformTags = value;
        }

        public BuildRunArgs()
        {
        }
        public static new BuildRunArgs Empty => new BuildRunArgs();
    }

    public sealed class BuildRunState : global::Pulumi.ResourceArgs
    {
        [Input("buildOutputs")]
        private InputList<Inputs.BuildRunBuildOutputGetArgs>? _buildOutputs;

        /// <summary>
        /// Outputs from the build.
        /// </summary>
        public InputList<Inputs.BuildRunBuildOutputGetArgs> BuildOutputs
        {
            get => _buildOutputs ?? (_buildOutputs = new InputList<Inputs.BuildRunBuildOutputGetArgs>());
            set => _buildOutputs = value;
        }

        /// <summary>
        /// The OCID of the build pipeline.
        /// </summary>
        [Input("buildPipelineId")]
        public Input<string>? BuildPipelineId { get; set; }

        /// <summary>
        /// Specifies list of arguments passed along with the build run.
        /// </summary>
        [Input("buildRunArguments")]
        public Input<Inputs.BuildRunBuildRunArgumentsGetArgs>? BuildRunArguments { get; set; }

        [Input("buildRunProgresses")]
        private InputList<Inputs.BuildRunBuildRunProgressGetArgs>? _buildRunProgresses;

        /// <summary>
        /// The run progress details of a build run.
        /// </summary>
        public InputList<Inputs.BuildRunBuildRunProgressGetArgs> BuildRunProgresses
        {
            get => _buildRunProgresses ?? (_buildRunProgresses = new InputList<Inputs.BuildRunBuildRunProgressGetArgs>());
            set => _buildRunProgresses = value;
        }

        [Input("buildRunSources")]
        private InputList<Inputs.BuildRunBuildRunSourceGetArgs>? _buildRunSources;

        /// <summary>
        /// The source from which the build run is triggered.
        /// </summary>
        public InputList<Inputs.BuildRunBuildRunSourceGetArgs> BuildRunSources
        {
            get => _buildRunSources ?? (_buildRunSources = new InputList<Inputs.BuildRunBuildRunSourceGetArgs>());
            set => _buildRunSources = value;
        }

        /// <summary>
        /// Commit details that need to be used for the build run.
        /// </summary>
        [Input("commitInfo")]
        public Input<Inputs.BuildRunCommitInfoGetArgs>? CommitInfo { get; set; }

        /// <summary>
        /// The OCID of the compartment where the build is running.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        [Input("definedTags")]
        private InputMap<object>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public InputMap<object> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<object>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) Build run display name, which can be renamed and is not necessarily unique. Avoid entering confidential information.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("freeformTags")]
        private InputMap<object>? _freeformTags;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
        /// </summary>
        public InputMap<object> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<object>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        [Input("lifecycleDetails")]
        public Input<string>? LifecycleDetails { get; set; }

        /// <summary>
        /// The OCID of the DevOps project.
        /// </summary>
        [Input("projectId")]
        public Input<string>? ProjectId { get; set; }

        /// <summary>
        /// The current state of the build run.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        [Input("systemTags")]
        private InputMap<object>? _systemTags;

        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public InputMap<object> SystemTags
        {
            get => _systemTags ?? (_systemTags = new InputMap<object>());
            set => _systemTags = value;
        }

        /// <summary>
        /// The time the build run was created. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// The time the build run was updated. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
        /// </summary>
        [Input("timeUpdated")]
        public Input<string>? TimeUpdated { get; set; }

        public BuildRunState()
        {
        }
        public static new BuildRunState Empty => new BuildRunState();
    }
}