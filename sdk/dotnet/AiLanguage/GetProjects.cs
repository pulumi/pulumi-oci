// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.AiLanguage
{
    public static class GetProjects
    {
        /// <summary>
        /// This data source provides the list of Projects in Oracle Cloud Infrastructure Ai Language service.
        /// 
        /// Returns a list of  Projects.
        /// </summary>
        public static Task<GetProjectsResult> InvokeAsync(GetProjectsArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetProjectsResult>("oci:AiLanguage/getProjects:getProjects", args ?? new GetProjectsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Projects in Oracle Cloud Infrastructure Ai Language service.
        /// 
        /// Returns a list of  Projects.
        /// </summary>
        public static Output<GetProjectsResult> Invoke(GetProjectsInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetProjectsResult>("oci:AiLanguage/getProjects:getProjects", args ?? new GetProjectsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetProjectsArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The ID of the compartment in which to list resources.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// A filter to return only resources that match the entire display name given.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetProjectsFilterArgs>? _filters;
        public List<Inputs.GetProjectsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetProjectsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// Unique identifier OCID of the project
        /// </summary>
        [Input("id")]
        public string? Id { get; set; }

        /// <summary>
        /// &lt;b&gt;Filter&lt;/b&gt; results by the specified lifecycle state. Must be a valid state for the resource type.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        public GetProjectsArgs()
        {
        }
        public static new GetProjectsArgs Empty => new GetProjectsArgs();
    }

    public sealed class GetProjectsInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The ID of the compartment in which to list resources.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// A filter to return only resources that match the entire display name given.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetProjectsFilterInputArgs>? _filters;
        public InputList<Inputs.GetProjectsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetProjectsFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// Unique identifier OCID of the project
        /// </summary>
        [Input("id")]
        public Input<string>? Id { get; set; }

        /// <summary>
        /// &lt;b&gt;Filter&lt;/b&gt; results by the specified lifecycle state. Must be a valid state for the resource type.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        public GetProjectsInvokeArgs()
        {
        }
        public static new GetProjectsInvokeArgs Empty => new GetProjectsInvokeArgs();
    }


    [OutputType]
    public sealed class GetProjectsResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)  for the project's compartment.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// A user-friendly display name for the resource. It does not have to be unique and can be modified. Avoid entering confidential information.
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetProjectsFilterResult> Filters;
        /// <summary>
        /// Unique identifier OCID of the project
        /// </summary>
        public readonly string? Id;
        /// <summary>
        /// The list of project_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetProjectsProjectCollectionResult> ProjectCollections;
        /// <summary>
        /// The state of the project.
        /// </summary>
        public readonly string? State;

        [OutputConstructor]
        private GetProjectsResult(
            string compartmentId,

            string? displayName,

            ImmutableArray<Outputs.GetProjectsFilterResult> filters,

            string? id,

            ImmutableArray<Outputs.GetProjectsProjectCollectionResult> projectCollections,

            string? state)
        {
            CompartmentId = compartmentId;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            ProjectCollections = projectCollections;
            State = state;
        }
    }
}