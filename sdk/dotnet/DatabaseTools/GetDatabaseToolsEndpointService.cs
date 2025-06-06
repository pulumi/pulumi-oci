// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseTools
{
    public static class GetDatabaseToolsEndpointService
    {
        /// <summary>
        /// This data source provides details about a specific Database Tools Endpoint Service resource in Oracle Cloud Infrastructure Database Tools service.
        /// 
        /// Gets details for the specified Database Tools endpoint service.
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
        ///     var testDatabaseToolsEndpointService = Oci.DatabaseTools.GetDatabaseToolsEndpointService.Invoke(new()
        ///     {
        ///         DatabaseToolsEndpointServiceId = testDatabaseToolsEndpointServiceOciDatabaseToolsDatabaseToolsEndpointService.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetDatabaseToolsEndpointServiceResult> InvokeAsync(GetDatabaseToolsEndpointServiceArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetDatabaseToolsEndpointServiceResult>("oci:DatabaseTools/getDatabaseToolsEndpointService:getDatabaseToolsEndpointService", args ?? new GetDatabaseToolsEndpointServiceArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Database Tools Endpoint Service resource in Oracle Cloud Infrastructure Database Tools service.
        /// 
        /// Gets details for the specified Database Tools endpoint service.
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
        ///     var testDatabaseToolsEndpointService = Oci.DatabaseTools.GetDatabaseToolsEndpointService.Invoke(new()
        ///     {
        ///         DatabaseToolsEndpointServiceId = testDatabaseToolsEndpointServiceOciDatabaseToolsDatabaseToolsEndpointService.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetDatabaseToolsEndpointServiceResult> Invoke(GetDatabaseToolsEndpointServiceInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetDatabaseToolsEndpointServiceResult>("oci:DatabaseTools/getDatabaseToolsEndpointService:getDatabaseToolsEndpointService", args ?? new GetDatabaseToolsEndpointServiceInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Database Tools Endpoint Service resource in Oracle Cloud Infrastructure Database Tools service.
        /// 
        /// Gets details for the specified Database Tools endpoint service.
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
        ///     var testDatabaseToolsEndpointService = Oci.DatabaseTools.GetDatabaseToolsEndpointService.Invoke(new()
        ///     {
        ///         DatabaseToolsEndpointServiceId = testDatabaseToolsEndpointServiceOciDatabaseToolsDatabaseToolsEndpointService.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetDatabaseToolsEndpointServiceResult> Invoke(GetDatabaseToolsEndpointServiceInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetDatabaseToolsEndpointServiceResult>("oci:DatabaseTools/getDatabaseToolsEndpointService:getDatabaseToolsEndpointService", args ?? new GetDatabaseToolsEndpointServiceInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetDatabaseToolsEndpointServiceArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a Database Tools Endpoint Service.
        /// </summary>
        [Input("databaseToolsEndpointServiceId", required: true)]
        public string DatabaseToolsEndpointServiceId { get; set; } = null!;

        public GetDatabaseToolsEndpointServiceArgs()
        {
        }
        public static new GetDatabaseToolsEndpointServiceArgs Empty => new GetDatabaseToolsEndpointServiceArgs();
    }

    public sealed class GetDatabaseToolsEndpointServiceInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a Database Tools Endpoint Service.
        /// </summary>
        [Input("databaseToolsEndpointServiceId", required: true)]
        public Input<string> DatabaseToolsEndpointServiceId { get; set; } = null!;

        public GetDatabaseToolsEndpointServiceInvokeArgs()
        {
        }
        public static new GetDatabaseToolsEndpointServiceInvokeArgs Empty => new GetDatabaseToolsEndpointServiceInvokeArgs();
    }


    [OutputType]
    public sealed class GetDatabaseToolsEndpointServiceResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the Database Tools Endpoint Service.
        /// </summary>
        public readonly string CompartmentId;
        public readonly string DatabaseToolsEndpointServiceId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// A description of the Database Tools Endpoint Service.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// A unique, non-changeable resource name.
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// The current state of the Database Tools Endpoint Service.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> SystemTags;
        /// <summary>
        /// The time the Database Tools Endpoint Service was created. An RFC3339 formatted datetime string
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The time the Database Tools Endpoint Service was updated. An RFC3339 formatted datetime string
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetDatabaseToolsEndpointServiceResult(
            string compartmentId,

            string databaseToolsEndpointServiceId,

            ImmutableDictionary<string, string> definedTags,

            string description,

            string displayName,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            string lifecycleDetails,

            string name,

            string state,

            ImmutableDictionary<string, string> systemTags,

            string timeCreated,

            string timeUpdated)
        {
            CompartmentId = compartmentId;
            DatabaseToolsEndpointServiceId = databaseToolsEndpointServiceId;
            DefinedTags = definedTags;
            Description = description;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            LifecycleDetails = lifecycleDetails;
            Name = name;
            State = state;
            SystemTags = systemTags;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
        }
    }
}
