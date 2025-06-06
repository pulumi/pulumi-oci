// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DevOps
{
    public static class GetBuildPipelineStages
    {
        /// <summary>
        /// This data source provides the list of Build Pipeline Stages in Oracle Cloud Infrastructure Devops service.
        /// 
        /// Returns a list of all stages in a compartment or build pipeline.
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
        ///     var testBuildPipelineStages = Oci.DevOps.GetBuildPipelineStages.Invoke(new()
        ///     {
        ///         BuildPipelineId = testBuildPipeline.Id,
        ///         CompartmentId = compartmentId,
        ///         DisplayName = buildPipelineStageDisplayName,
        ///         Id = buildPipelineStageId,
        ///         State = buildPipelineStageState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetBuildPipelineStagesResult> InvokeAsync(GetBuildPipelineStagesArgs? args = null, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetBuildPipelineStagesResult>("oci:DevOps/getBuildPipelineStages:getBuildPipelineStages", args ?? new GetBuildPipelineStagesArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Build Pipeline Stages in Oracle Cloud Infrastructure Devops service.
        /// 
        /// Returns a list of all stages in a compartment or build pipeline.
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
        ///     var testBuildPipelineStages = Oci.DevOps.GetBuildPipelineStages.Invoke(new()
        ///     {
        ///         BuildPipelineId = testBuildPipeline.Id,
        ///         CompartmentId = compartmentId,
        ///         DisplayName = buildPipelineStageDisplayName,
        ///         Id = buildPipelineStageId,
        ///         State = buildPipelineStageState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetBuildPipelineStagesResult> Invoke(GetBuildPipelineStagesInvokeArgs? args = null, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetBuildPipelineStagesResult>("oci:DevOps/getBuildPipelineStages:getBuildPipelineStages", args ?? new GetBuildPipelineStagesInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Build Pipeline Stages in Oracle Cloud Infrastructure Devops service.
        /// 
        /// Returns a list of all stages in a compartment or build pipeline.
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
        ///     var testBuildPipelineStages = Oci.DevOps.GetBuildPipelineStages.Invoke(new()
        ///     {
        ///         BuildPipelineId = testBuildPipeline.Id,
        ///         CompartmentId = compartmentId,
        ///         DisplayName = buildPipelineStageDisplayName,
        ///         Id = buildPipelineStageId,
        ///         State = buildPipelineStageState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetBuildPipelineStagesResult> Invoke(GetBuildPipelineStagesInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetBuildPipelineStagesResult>("oci:DevOps/getBuildPipelineStages:getBuildPipelineStages", args ?? new GetBuildPipelineStagesInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetBuildPipelineStagesArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the parent build pipeline.
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
        private List<Inputs.GetBuildPipelineStagesFilterArgs>? _filters;
        public List<Inputs.GetBuildPipelineStagesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetBuildPipelineStagesFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// Unique identifier or OCID for listing a single resource by ID.
        /// </summary>
        [Input("id")]
        public string? Id { get; set; }

        /// <summary>
        /// A filter to return the stages that matches the given lifecycle state.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        public GetBuildPipelineStagesArgs()
        {
        }
        public static new GetBuildPipelineStagesArgs Empty => new GetBuildPipelineStagesArgs();
    }

    public sealed class GetBuildPipelineStagesInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the parent build pipeline.
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
        private InputList<Inputs.GetBuildPipelineStagesFilterInputArgs>? _filters;
        public InputList<Inputs.GetBuildPipelineStagesFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetBuildPipelineStagesFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// Unique identifier or OCID for listing a single resource by ID.
        /// </summary>
        [Input("id")]
        public Input<string>? Id { get; set; }

        /// <summary>
        /// A filter to return the stages that matches the given lifecycle state.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        public GetBuildPipelineStagesInvokeArgs()
        {
        }
        public static new GetBuildPipelineStagesInvokeArgs Empty => new GetBuildPipelineStagesInvokeArgs();
    }


    [OutputType]
    public sealed class GetBuildPipelineStagesResult
    {
        /// <summary>
        /// The OCID of the build pipeline.
        /// </summary>
        public readonly string? BuildPipelineId;
        /// <summary>
        /// The list of build_pipeline_stage_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetBuildPipelineStagesBuildPipelineStageCollectionResult> BuildPipelineStageCollections;
        /// <summary>
        /// The OCID of the compartment where the pipeline is created.
        /// </summary>
        public readonly string? CompartmentId;
        /// <summary>
        /// Stage display name, which can be renamed and is not necessarily unique. Avoid entering confidential information.
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetBuildPipelineStagesFilterResult> Filters;
        /// <summary>
        /// Unique identifier that is immutable on creation.
        /// </summary>
        public readonly string? Id;
        /// <summary>
        /// The current state of the stage.
        /// </summary>
        public readonly string? State;

        [OutputConstructor]
        private GetBuildPipelineStagesResult(
            string? buildPipelineId,

            ImmutableArray<Outputs.GetBuildPipelineStagesBuildPipelineStageCollectionResult> buildPipelineStageCollections,

            string? compartmentId,

            string? displayName,

            ImmutableArray<Outputs.GetBuildPipelineStagesFilterResult> filters,

            string? id,

            string? state)
        {
            BuildPipelineId = buildPipelineId;
            BuildPipelineStageCollections = buildPipelineStageCollections;
            CompartmentId = compartmentId;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            State = state;
        }
    }
}
