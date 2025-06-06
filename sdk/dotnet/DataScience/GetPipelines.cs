// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataScience
{
    public static class GetPipelines
    {
        /// <summary>
        /// This data source provides the list of Pipelines in Oracle Cloud Infrastructure Data Science service.
        /// 
        /// Returns a list of Pipelines.
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
        ///     var testPipelines = Oci.DataScience.GetPipelines.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         CreatedBy = pipelineCreatedBy,
        ///         DisplayName = pipelineDisplayName,
        ///         Id = pipelineId,
        ///         ProjectId = testProject.Id,
        ///         State = pipelineState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetPipelinesResult> InvokeAsync(GetPipelinesArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetPipelinesResult>("oci:DataScience/getPipelines:getPipelines", args ?? new GetPipelinesArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Pipelines in Oracle Cloud Infrastructure Data Science service.
        /// 
        /// Returns a list of Pipelines.
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
        ///     var testPipelines = Oci.DataScience.GetPipelines.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         CreatedBy = pipelineCreatedBy,
        ///         DisplayName = pipelineDisplayName,
        ///         Id = pipelineId,
        ///         ProjectId = testProject.Id,
        ///         State = pipelineState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetPipelinesResult> Invoke(GetPipelinesInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetPipelinesResult>("oci:DataScience/getPipelines:getPipelines", args ?? new GetPipelinesInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Pipelines in Oracle Cloud Infrastructure Data Science service.
        /// 
        /// Returns a list of Pipelines.
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
        ///     var testPipelines = Oci.DataScience.GetPipelines.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         CreatedBy = pipelineCreatedBy,
        ///         DisplayName = pipelineDisplayName,
        ///         Id = pipelineId,
        ///         ProjectId = testProject.Id,
        ///         State = pipelineState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetPipelinesResult> Invoke(GetPipelinesInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetPipelinesResult>("oci:DataScience/getPipelines:getPipelines", args ?? new GetPipelinesInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetPipelinesArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// &lt;b&gt;Filter&lt;/b&gt; results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// &lt;b&gt;Filter&lt;/b&gt; results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the resource.
        /// </summary>
        [Input("createdBy")]
        public string? CreatedBy { get; set; }

        /// <summary>
        /// &lt;b&gt;Filter&lt;/b&gt; results by its user-friendly name.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetPipelinesFilterArgs>? _filters;
        public List<Inputs.GetPipelinesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetPipelinesFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// &lt;b&gt;Filter&lt;/b&gt; results by [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). Must be an OCID of the correct type for the resource type.
        /// </summary>
        [Input("id")]
        public string? Id { get; set; }

        /// <summary>
        /// &lt;b&gt;Filter&lt;/b&gt; results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project.
        /// </summary>
        [Input("projectId")]
        public string? ProjectId { get; set; }

        /// <summary>
        /// The current state of the Pipeline.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        public GetPipelinesArgs()
        {
        }
        public static new GetPipelinesArgs Empty => new GetPipelinesArgs();
    }

    public sealed class GetPipelinesInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// &lt;b&gt;Filter&lt;/b&gt; results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// &lt;b&gt;Filter&lt;/b&gt; results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the resource.
        /// </summary>
        [Input("createdBy")]
        public Input<string>? CreatedBy { get; set; }

        /// <summary>
        /// &lt;b&gt;Filter&lt;/b&gt; results by its user-friendly name.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetPipelinesFilterInputArgs>? _filters;
        public InputList<Inputs.GetPipelinesFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetPipelinesFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// &lt;b&gt;Filter&lt;/b&gt; results by [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). Must be an OCID of the correct type for the resource type.
        /// </summary>
        [Input("id")]
        public Input<string>? Id { get; set; }

        /// <summary>
        /// &lt;b&gt;Filter&lt;/b&gt; results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project.
        /// </summary>
        [Input("projectId")]
        public Input<string>? ProjectId { get; set; }

        /// <summary>
        /// The current state of the Pipeline.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        public GetPipelinesInvokeArgs()
        {
        }
        public static new GetPipelinesInvokeArgs Empty => new GetPipelinesInvokeArgs();
    }


    [OutputType]
    public sealed class GetPipelinesResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want to create the pipeline.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the pipeline.
        /// </summary>
        public readonly string? CreatedBy;
        /// <summary>
        /// A user-friendly display name for the resource.
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetPipelinesFilterResult> Filters;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the pipeline.
        /// </summary>
        public readonly string? Id;
        /// <summary>
        /// The list of pipelines.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetPipelinesPipelineResult> Pipelines;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate the pipeline with.
        /// </summary>
        public readonly string? ProjectId;
        /// <summary>
        /// The current state of the pipeline.
        /// </summary>
        public readonly string? State;

        [OutputConstructor]
        private GetPipelinesResult(
            string compartmentId,

            string? createdBy,

            string? displayName,

            ImmutableArray<Outputs.GetPipelinesFilterResult> filters,

            string? id,

            ImmutableArray<Outputs.GetPipelinesPipelineResult> pipelines,

            string? projectId,

            string? state)
        {
            CompartmentId = compartmentId;
            CreatedBy = createdBy;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            Pipelines = pipelines;
            ProjectId = projectId;
            State = state;
        }
    }
}
