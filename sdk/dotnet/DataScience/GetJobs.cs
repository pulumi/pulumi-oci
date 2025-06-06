// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataScience
{
    public static class GetJobs
    {
        /// <summary>
        /// This data source provides the list of Jobs in Oracle Cloud Infrastructure Data Science service.
        /// 
        /// List jobs in the specified compartment.
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
        ///     var testJobs = Oci.DataScience.GetJobs.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         CreatedBy = jobCreatedBy,
        ///         DisplayName = jobDisplayName,
        ///         Id = jobId,
        ///         ProjectId = testProject.Id,
        ///         State = jobState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetJobsResult> InvokeAsync(GetJobsArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetJobsResult>("oci:DataScience/getJobs:getJobs", args ?? new GetJobsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Jobs in Oracle Cloud Infrastructure Data Science service.
        /// 
        /// List jobs in the specified compartment.
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
        ///     var testJobs = Oci.DataScience.GetJobs.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         CreatedBy = jobCreatedBy,
        ///         DisplayName = jobDisplayName,
        ///         Id = jobId,
        ///         ProjectId = testProject.Id,
        ///         State = jobState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetJobsResult> Invoke(GetJobsInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetJobsResult>("oci:DataScience/getJobs:getJobs", args ?? new GetJobsInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Jobs in Oracle Cloud Infrastructure Data Science service.
        /// 
        /// List jobs in the specified compartment.
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
        ///     var testJobs = Oci.DataScience.GetJobs.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         CreatedBy = jobCreatedBy,
        ///         DisplayName = jobDisplayName,
        ///         Id = jobId,
        ///         ProjectId = testProject.Id,
        ///         State = jobState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetJobsResult> Invoke(GetJobsInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetJobsResult>("oci:DataScience/getJobs:getJobs", args ?? new GetJobsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetJobsArgs : global::Pulumi.InvokeArgs
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
        private List<Inputs.GetJobsFilterArgs>? _filters;
        public List<Inputs.GetJobsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetJobsFilterArgs>());
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
        /// &lt;b&gt;Filter&lt;/b&gt; results by the specified lifecycle state. Must be a valid state for the resource type.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        public GetJobsArgs()
        {
        }
        public static new GetJobsArgs Empty => new GetJobsArgs();
    }

    public sealed class GetJobsInvokeArgs : global::Pulumi.InvokeArgs
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
        private InputList<Inputs.GetJobsFilterInputArgs>? _filters;
        public InputList<Inputs.GetJobsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetJobsFilterInputArgs>());
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
        /// &lt;b&gt;Filter&lt;/b&gt; results by the specified lifecycle state. Must be a valid state for the resource type.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        public GetJobsInvokeArgs()
        {
        }
        public static new GetJobsInvokeArgs Empty => new GetJobsInvokeArgs();
    }


    [OutputType]
    public sealed class GetJobsResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want to create the job.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the project.
        /// </summary>
        public readonly string? CreatedBy;
        /// <summary>
        /// A user-friendly display name for the resource.
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetJobsFilterResult> Filters;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the job.
        /// </summary>
        public readonly string? Id;
        /// <summary>
        /// The list of jobs.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetJobsJobResult> Jobs;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate the job with.
        /// </summary>
        public readonly string? ProjectId;
        /// <summary>
        /// The state of the job.
        /// </summary>
        public readonly string? State;

        [OutputConstructor]
        private GetJobsResult(
            string compartmentId,

            string? createdBy,

            string? displayName,

            ImmutableArray<Outputs.GetJobsFilterResult> filters,

            string? id,

            ImmutableArray<Outputs.GetJobsJobResult> jobs,

            string? projectId,

            string? state)
        {
            CompartmentId = compartmentId;
            CreatedBy = createdBy;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            Jobs = jobs;
            ProjectId = projectId;
            State = state;
        }
    }
}
