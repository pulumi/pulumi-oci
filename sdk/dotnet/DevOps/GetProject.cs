// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DevOps
{
    public static class GetProject
    {
        /// <summary>
        /// This data source provides details about a specific Project resource in Oracle Cloud Infrastructure Devops service.
        /// 
        /// Retrieves a project by identifier.
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
        ///     var testProject = Oci.DevOps.GetProject.Invoke(new()
        ///     {
        ///         ProjectId = testProjectOciDevopsProject.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetProjectResult> InvokeAsync(GetProjectArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetProjectResult>("oci:DevOps/getProject:getProject", args ?? new GetProjectArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Project resource in Oracle Cloud Infrastructure Devops service.
        /// 
        /// Retrieves a project by identifier.
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
        ///     var testProject = Oci.DevOps.GetProject.Invoke(new()
        ///     {
        ///         ProjectId = testProjectOciDevopsProject.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetProjectResult> Invoke(GetProjectInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetProjectResult>("oci:DevOps/getProject:getProject", args ?? new GetProjectInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Project resource in Oracle Cloud Infrastructure Devops service.
        /// 
        /// Retrieves a project by identifier.
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
        ///     var testProject = Oci.DevOps.GetProject.Invoke(new()
        ///     {
        ///         ProjectId = testProjectOciDevopsProject.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetProjectResult> Invoke(GetProjectInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetProjectResult>("oci:DevOps/getProject:getProject", args ?? new GetProjectInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetProjectArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// Unique project identifier.
        /// </summary>
        [Input("projectId", required: true)]
        public string ProjectId { get; set; } = null!;

        public GetProjectArgs()
        {
        }
        public static new GetProjectArgs Empty => new GetProjectArgs();
    }

    public sealed class GetProjectInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// Unique project identifier.
        /// </summary>
        [Input("projectId", required: true)]
        public Input<string> ProjectId { get; set; } = null!;

        public GetProjectInvokeArgs()
        {
        }
        public static new GetProjectInvokeArgs Empty => new GetProjectInvokeArgs();
    }


    [OutputType]
    public sealed class GetProjectResult
    {
        /// <summary>
        /// The OCID of the compartment where the project is created.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// Project description.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// Unique identifier that is immutable on creation.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// Project name (case-sensitive).
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// Namespace associated with the project.
        /// </summary>
        public readonly string Namespace;
        /// <summary>
        /// Notification configuration for the project.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetProjectNotificationConfigResult> NotificationConfigs;
        public readonly string ProjectId;
        /// <summary>
        /// The current state of the project.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> SystemTags;
        /// <summary>
        /// Time the project was created. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// Time the project was updated. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetProjectResult(
            string compartmentId,

            ImmutableDictionary<string, string> definedTags,

            string description,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            string lifecycleDetails,

            string name,

            string @namespace,

            ImmutableArray<Outputs.GetProjectNotificationConfigResult> notificationConfigs,

            string projectId,

            string state,

            ImmutableDictionary<string, string> systemTags,

            string timeCreated,

            string timeUpdated)
        {
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            Description = description;
            FreeformTags = freeformTags;
            Id = id;
            LifecycleDetails = lifecycleDetails;
            Name = name;
            Namespace = @namespace;
            NotificationConfigs = notificationConfigs;
            ProjectId = projectId;
            State = state;
            SystemTags = systemTags;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
        }
    }
}
