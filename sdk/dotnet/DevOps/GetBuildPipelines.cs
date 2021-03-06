// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DevOps
{
    public static class GetBuildPipelines
    {
        /// <summary>
        /// This data source provides the list of Build Pipelines in Oracle Cloud Infrastructure Devops service.
        /// 
        /// Returns a list of build pipelines.
        /// 
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// class MyStack : Stack
        /// {
        ///     public MyStack()
        ///     {
        ///         var testBuildPipelines = Output.Create(Oci.DevOps.GetBuildPipelines.InvokeAsync(new Oci.DevOps.GetBuildPipelinesArgs
        ///         {
        ///             CompartmentId = @var.Compartment_id,
        ///             DisplayName = @var.Build_pipeline_display_name,
        ///             Id = @var.Build_pipeline_id,
        ///             ProjectId = oci_devops_project.Test_project.Id,
        ///             State = @var.Build_pipeline_state,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetBuildPipelinesResult> InvokeAsync(GetBuildPipelinesArgs? args = null, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetBuildPipelinesResult>("oci:DevOps/getBuildPipelines:getBuildPipelines", args ?? new GetBuildPipelinesArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Build Pipelines in Oracle Cloud Infrastructure Devops service.
        /// 
        /// Returns a list of build pipelines.
        /// 
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// class MyStack : Stack
        /// {
        ///     public MyStack()
        ///     {
        ///         var testBuildPipelines = Output.Create(Oci.DevOps.GetBuildPipelines.InvokeAsync(new Oci.DevOps.GetBuildPipelinesArgs
        ///         {
        ///             CompartmentId = @var.Compartment_id,
        ///             DisplayName = @var.Build_pipeline_display_name,
        ///             Id = @var.Build_pipeline_id,
        ///             ProjectId = oci_devops_project.Test_project.Id,
        ///             State = @var.Build_pipeline_state,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetBuildPipelinesResult> Invoke(GetBuildPipelinesInvokeArgs? args = null, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetBuildPipelinesResult>("oci:DevOps/getBuildPipelines:getBuildPipelines", args ?? new GetBuildPipelinesInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetBuildPipelinesArgs : Pulumi.InvokeArgs
    {
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
        private List<Inputs.GetBuildPipelinesFilterArgs>? _filters;
        public List<Inputs.GetBuildPipelinesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetBuildPipelinesFilterArgs>());
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
        /// A filter to return only build pipelines that matches the given lifecycle state.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        public GetBuildPipelinesArgs()
        {
        }
    }

    public sealed class GetBuildPipelinesInvokeArgs : Pulumi.InvokeArgs
    {
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
        private InputList<Inputs.GetBuildPipelinesFilterInputArgs>? _filters;
        public InputList<Inputs.GetBuildPipelinesFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetBuildPipelinesFilterInputArgs>());
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
        /// A filter to return only build pipelines that matches the given lifecycle state.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        public GetBuildPipelinesInvokeArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetBuildPipelinesResult
    {
        /// <summary>
        /// The list of build_pipeline_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetBuildPipelinesBuildPipelineCollectionResult> BuildPipelineCollections;
        /// <summary>
        /// The OCID of the compartment where the build pipeline is created.
        /// </summary>
        public readonly string? CompartmentId;
        /// <summary>
        /// Build pipeline display name, which can be renamed and is not necessarily unique. Avoid entering confidential information.
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetBuildPipelinesFilterResult> Filters;
        /// <summary>
        /// Unique identifier that is immutable on creation.
        /// </summary>
        public readonly string? Id;
        /// <summary>
        /// The OCID of the DevOps project.
        /// </summary>
        public readonly string? ProjectId;
        /// <summary>
        /// The current state of the build pipeline.
        /// </summary>
        public readonly string? State;

        [OutputConstructor]
        private GetBuildPipelinesResult(
            ImmutableArray<Outputs.GetBuildPipelinesBuildPipelineCollectionResult> buildPipelineCollections,

            string? compartmentId,

            string? displayName,

            ImmutableArray<Outputs.GetBuildPipelinesFilterResult> filters,

            string? id,

            string? projectId,

            string? state)
        {
            BuildPipelineCollections = buildPipelineCollections;
            CompartmentId = compartmentId;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            ProjectId = projectId;
            State = state;
        }
    }
}
