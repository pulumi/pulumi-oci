// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataIntegration
{
    public static class GetWorkspaces
    {
        /// <summary>
        /// This data source provides the list of Workspaces in Oracle Cloud Infrastructure Data Integration service.
        /// 
        /// Retrieves a list of Data Integration workspaces.
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
        ///     var testWorkspaces = Oci.DataIntegration.GetWorkspaces.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         Name = workspaceName,
        ///         State = workspaceState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetWorkspacesResult> InvokeAsync(GetWorkspacesArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetWorkspacesResult>("oci:DataIntegration/getWorkspaces:getWorkspaces", args ?? new GetWorkspacesArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Workspaces in Oracle Cloud Infrastructure Data Integration service.
        /// 
        /// Retrieves a list of Data Integration workspaces.
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
        ///     var testWorkspaces = Oci.DataIntegration.GetWorkspaces.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         Name = workspaceName,
        ///         State = workspaceState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetWorkspacesResult> Invoke(GetWorkspacesInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetWorkspacesResult>("oci:DataIntegration/getWorkspaces:getWorkspaces", args ?? new GetWorkspacesInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Workspaces in Oracle Cloud Infrastructure Data Integration service.
        /// 
        /// Retrieves a list of Data Integration workspaces.
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
        ///     var testWorkspaces = Oci.DataIntegration.GetWorkspaces.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         Name = workspaceName,
        ///         State = workspaceState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetWorkspacesResult> Invoke(GetWorkspacesInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetWorkspacesResult>("oci:DataIntegration/getWorkspaces:getWorkspaces", args ?? new GetWorkspacesInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetWorkspacesArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the compartment containing the resources you want to list.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        [Input("filters")]
        private List<Inputs.GetWorkspacesFilterArgs>? _filters;
        public List<Inputs.GetWorkspacesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetWorkspacesFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// Used to filter by the name of the object.
        /// </summary>
        [Input("name")]
        public string? Name { get; set; }

        /// <summary>
        /// The lifecycle state of a resource. When specified, the operation only returns resources that match the given lifecycle state. When not specified, all lifecycle states are processed as a match.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        public GetWorkspacesArgs()
        {
        }
        public static new GetWorkspacesArgs Empty => new GetWorkspacesArgs();
    }

    public sealed class GetWorkspacesInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the compartment containing the resources you want to list.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        [Input("filters")]
        private InputList<Inputs.GetWorkspacesFilterInputArgs>? _filters;
        public InputList<Inputs.GetWorkspacesFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetWorkspacesFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// Used to filter by the name of the object.
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// The lifecycle state of a resource. When specified, the operation only returns resources that match the given lifecycle state. When not specified, all lifecycle states are processed as a match.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        public GetWorkspacesInvokeArgs()
        {
        }
        public static new GetWorkspacesInvokeArgs Empty => new GetWorkspacesInvokeArgs();
    }


    [OutputType]
    public sealed class GetWorkspacesResult
    {
        /// <summary>
        /// The OCID of the compartment that contains the workspace.
        /// </summary>
        public readonly string CompartmentId;
        public readonly ImmutableArray<Outputs.GetWorkspacesFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly string? Name;
        /// <summary>
        /// Lifecycle states for workspaces in Data Integration Service CREATING - The resource is being created and may not be usable until the entire metadata is defined UPDATING - The resource is being updated and may not be usable until all changes are commited DELETING - The resource is being deleted and might require deep cleanup of children. ACTIVE   - The resource is valid and available for access INACTIVE - The resource might be incomplete in its definition or might have been made unavailable for administrative reasons DELETED  - The resource has been deleted and isn't available FAILED   - The resource is in a failed state due to validation or other errors STARTING - The resource is being started and may not be usable until becomes ACTIVE again STOPPING - The resource is in the process of Stopping and may not be usable until it Stops or fails STOPPED  - The resource is in Stopped state due to stop operation.
        /// </summary>
        public readonly string? State;
        /// <summary>
        /// The list of workspaces.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetWorkspacesWorkspaceResult> Workspaces;

        [OutputConstructor]
        private GetWorkspacesResult(
            string compartmentId,

            ImmutableArray<Outputs.GetWorkspacesFilterResult> filters,

            string id,

            string? name,

            string? state,

            ImmutableArray<Outputs.GetWorkspacesWorkspaceResult> workspaces)
        {
            CompartmentId = compartmentId;
            Filters = filters;
            Id = id;
            Name = name;
            State = state;
            Workspaces = workspaces;
        }
    }
}
