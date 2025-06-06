// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DevOps
{
    public static class GetBuildRuns
    {
        /// <summary>
        /// This data source provides the list of Build Runs in Oracle Cloud Infrastructure Devops service.
        /// 
        /// Returns a list of build run summary.
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
        ///     var testBuildRuns = Oci.DevOps.GetBuildRuns.Invoke(new()
        ///     {
        ///         BuildPipelineId = testBuildPipeline.Id,
        ///         CompartmentId = compartmentId,
        ///         DisplayName = buildRunDisplayName,
        ///         Id = buildRunId,
        ///         ProjectId = testProject.Id,
        ///         State = buildRunState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetBuildRunsResult> InvokeAsync(GetBuildRunsArgs? args = null, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetBuildRunsResult>("oci:DevOps/getBuildRuns:getBuildRuns", args ?? new GetBuildRunsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Build Runs in Oracle Cloud Infrastructure Devops service.
        /// 
        /// Returns a list of build run summary.
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
        ///     var testBuildRuns = Oci.DevOps.GetBuildRuns.Invoke(new()
        ///     {
        ///         BuildPipelineId = testBuildPipeline.Id,
        ///         CompartmentId = compartmentId,
        ///         DisplayName = buildRunDisplayName,
        ///         Id = buildRunId,
        ///         ProjectId = testProject.Id,
        ///         State = buildRunState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetBuildRunsResult> Invoke(GetBuildRunsInvokeArgs? args = null, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetBuildRunsResult>("oci:DevOps/getBuildRuns:getBuildRuns", args ?? new GetBuildRunsInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Build Runs in Oracle Cloud Infrastructure Devops service.
        /// 
        /// Returns a list of build run summary.
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
        ///     var testBuildRuns = Oci.DevOps.GetBuildRuns.Invoke(new()
        ///     {
        ///         BuildPipelineId = testBuildPipeline.Id,
        ///         CompartmentId = compartmentId,
        ///         DisplayName = buildRunDisplayName,
        ///         Id = buildRunId,
        ///         ProjectId = testProject.Id,
        ///         State = buildRunState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetBuildRunsResult> Invoke(GetBuildRunsInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetBuildRunsResult>("oci:DevOps/getBuildRuns:getBuildRuns", args ?? new GetBuildRunsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetBuildRunsArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// Unique build pipeline identifier.
        /// </summary>
        [Input("buildPipelineId")]
        public string? BuildPipelineId { get; set; }

        /// <summary>
        /// The OCID of the compartment in which to list resources.
        /// </summary>
        [Input("compartmentId")]
        public string? CompartmentId { get; set; }

        /// <summary>
        /// A filter to return only resources that match the entire display name given.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetBuildRunsFilterArgs>? _filters;
        public List<Inputs.GetBuildRunsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetBuildRunsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// Unique identifier or OCID for listing a single resource by ID.
        /// </summary>
        [Input("id")]
        public string? Id { get; set; }

        /// <summary>
        /// unique project identifier
        /// </summary>
        [Input("projectId")]
        public string? ProjectId { get; set; }

        /// <summary>
        /// A filter to return only build runs that matches the given lifecycle state.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        public GetBuildRunsArgs()
        {
        }
        public static new GetBuildRunsArgs Empty => new GetBuildRunsArgs();
    }

    public sealed class GetBuildRunsInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// Unique build pipeline identifier.
        /// </summary>
        [Input("buildPipelineId")]
        public Input<string>? BuildPipelineId { get; set; }

        /// <summary>
        /// The OCID of the compartment in which to list resources.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        /// <summary>
        /// A filter to return only resources that match the entire display name given.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetBuildRunsFilterInputArgs>? _filters;
        public InputList<Inputs.GetBuildRunsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetBuildRunsFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// Unique identifier or OCID for listing a single resource by ID.
        /// </summary>
        [Input("id")]
        public Input<string>? Id { get; set; }

        /// <summary>
        /// unique project identifier
        /// </summary>
        [Input("projectId")]
        public Input<string>? ProjectId { get; set; }

        /// <summary>
        /// A filter to return only build runs that matches the given lifecycle state.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        public GetBuildRunsInvokeArgs()
        {
        }
        public static new GetBuildRunsInvokeArgs Empty => new GetBuildRunsInvokeArgs();
    }


    [OutputType]
    public sealed class GetBuildRunsResult
    {
        /// <summary>
        /// The OCID of the build pipeline to be triggered.
        /// </summary>
        public readonly string? BuildPipelineId;
        /// <summary>
        /// The list of build_run_summary_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetBuildRunsBuildRunSummaryCollectionResult> BuildRunSummaryCollections;
        /// <summary>
        /// The OCID of the compartment where the build is running.
        /// </summary>
        public readonly string? CompartmentId;
        /// <summary>
        /// Build run display name, which can be renamed and is not necessarily unique. Avoid entering confidential information.
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetBuildRunsFilterResult> Filters;
        /// <summary>
        /// Unique identifier that is immutable on creation.
        /// </summary>
        public readonly string? Id;
        /// <summary>
        /// The OCID of the DevOps project.
        /// </summary>
        public readonly string? ProjectId;
        /// <summary>
        /// The current state of the build run.
        /// </summary>
        public readonly string? State;

        [OutputConstructor]
        private GetBuildRunsResult(
            string? buildPipelineId,

            ImmutableArray<Outputs.GetBuildRunsBuildRunSummaryCollectionResult> buildRunSummaryCollections,

            string? compartmentId,

            string? displayName,

            ImmutableArray<Outputs.GetBuildRunsFilterResult> filters,

            string? id,

            string? projectId,

            string? state)
        {
            BuildPipelineId = buildPipelineId;
            BuildRunSummaryCollections = buildRunSummaryCollections;
            CompartmentId = compartmentId;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            ProjectId = projectId;
            State = state;
        }
    }
}
