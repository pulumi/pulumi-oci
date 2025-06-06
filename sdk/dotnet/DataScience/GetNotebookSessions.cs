// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataScience
{
    public static class GetNotebookSessions
    {
        /// <summary>
        /// This data source provides the list of Notebook Sessions in Oracle Cloud Infrastructure Data Science service.
        /// 
        /// Lists the notebook sessions in the specified compartment.
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
        ///     var testNotebookSessions = Oci.DataScience.GetNotebookSessions.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         CreatedBy = notebookSessionCreatedBy,
        ///         DisplayName = notebookSessionDisplayName,
        ///         Id = notebookSessionId,
        ///         ProjectId = testProject.Id,
        ///         State = notebookSessionState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetNotebookSessionsResult> InvokeAsync(GetNotebookSessionsArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetNotebookSessionsResult>("oci:DataScience/getNotebookSessions:getNotebookSessions", args ?? new GetNotebookSessionsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Notebook Sessions in Oracle Cloud Infrastructure Data Science service.
        /// 
        /// Lists the notebook sessions in the specified compartment.
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
        ///     var testNotebookSessions = Oci.DataScience.GetNotebookSessions.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         CreatedBy = notebookSessionCreatedBy,
        ///         DisplayName = notebookSessionDisplayName,
        ///         Id = notebookSessionId,
        ///         ProjectId = testProject.Id,
        ///         State = notebookSessionState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetNotebookSessionsResult> Invoke(GetNotebookSessionsInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetNotebookSessionsResult>("oci:DataScience/getNotebookSessions:getNotebookSessions", args ?? new GetNotebookSessionsInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Notebook Sessions in Oracle Cloud Infrastructure Data Science service.
        /// 
        /// Lists the notebook sessions in the specified compartment.
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
        ///     var testNotebookSessions = Oci.DataScience.GetNotebookSessions.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         CreatedBy = notebookSessionCreatedBy,
        ///         DisplayName = notebookSessionDisplayName,
        ///         Id = notebookSessionId,
        ///         ProjectId = testProject.Id,
        ///         State = notebookSessionState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetNotebookSessionsResult> Invoke(GetNotebookSessionsInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetNotebookSessionsResult>("oci:DataScience/getNotebookSessions:getNotebookSessions", args ?? new GetNotebookSessionsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetNotebookSessionsArgs : global::Pulumi.InvokeArgs
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
        private List<Inputs.GetNotebookSessionsFilterArgs>? _filters;
        public List<Inputs.GetNotebookSessionsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetNotebookSessionsFilterArgs>());
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

        public GetNotebookSessionsArgs()
        {
        }
        public static new GetNotebookSessionsArgs Empty => new GetNotebookSessionsArgs();
    }

    public sealed class GetNotebookSessionsInvokeArgs : global::Pulumi.InvokeArgs
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
        private InputList<Inputs.GetNotebookSessionsFilterInputArgs>? _filters;
        public InputList<Inputs.GetNotebookSessionsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetNotebookSessionsFilterInputArgs>());
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

        public GetNotebookSessionsInvokeArgs()
        {
        }
        public static new GetNotebookSessionsInvokeArgs Empty => new GetNotebookSessionsInvokeArgs();
    }


    [OutputType]
    public sealed class GetNotebookSessionsResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the notebook session's compartment.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the notebook session.
        /// </summary>
        public readonly string? CreatedBy;
        /// <summary>
        /// A user-friendly display name for the resource. It does not have to be unique and can be modified. Avoid entering confidential information. Example: `My NotebookSession`
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetNotebookSessionsFilterResult> Filters;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the notebook session.
        /// </summary>
        public readonly string? Id;
        /// <summary>
        /// The list of notebook_sessions.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetNotebookSessionsNotebookSessionResult> NotebookSessions;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project associated with the notebook session.
        /// </summary>
        public readonly string? ProjectId;
        /// <summary>
        /// The state of the notebook session.
        /// </summary>
        public readonly string? State;

        [OutputConstructor]
        private GetNotebookSessionsResult(
            string compartmentId,

            string? createdBy,

            string? displayName,

            ImmutableArray<Outputs.GetNotebookSessionsFilterResult> filters,

            string? id,

            ImmutableArray<Outputs.GetNotebookSessionsNotebookSessionResult> notebookSessions,

            string? projectId,

            string? state)
        {
            CompartmentId = compartmentId;
            CreatedBy = createdBy;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            NotebookSessions = notebookSessions;
            ProjectId = projectId;
            State = state;
        }
    }
}
