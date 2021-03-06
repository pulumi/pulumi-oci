// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataConnectivity
{
    public static class GetRegistry
    {
        /// <summary>
        /// This data source provides details about a specific Registry resource in Oracle Cloud Infrastructure Data Connectivity service.
        /// 
        /// Gets a Data Connectivity Management Registry by identifier
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
        ///         var testRegistry = Output.Create(Oci.DataConnectivity.GetRegistry.InvokeAsync(new Oci.DataConnectivity.GetRegistryArgs
        ///         {
        ///             RegistryId = oci_data_connectivity_registry.Test_registry.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetRegistryResult> InvokeAsync(GetRegistryArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetRegistryResult>("oci:DataConnectivity/getRegistry:getRegistry", args ?? new GetRegistryArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Registry resource in Oracle Cloud Infrastructure Data Connectivity service.
        /// 
        /// Gets a Data Connectivity Management Registry by identifier
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
        ///         var testRegistry = Output.Create(Oci.DataConnectivity.GetRegistry.InvokeAsync(new Oci.DataConnectivity.GetRegistryArgs
        ///         {
        ///             RegistryId = oci_data_connectivity_registry.Test_registry.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetRegistryResult> Invoke(GetRegistryInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetRegistryResult>("oci:DataConnectivity/getRegistry:getRegistry", args ?? new GetRegistryInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetRegistryArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The registry Ocid.
        /// </summary>
        [Input("registryId", required: true)]
        public string RegistryId { get; set; } = null!;

        public GetRegistryArgs()
        {
        }
    }

    public sealed class GetRegistryInvokeArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The registry Ocid.
        /// </summary>
        [Input("registryId", required: true)]
        public Input<string> RegistryId { get; set; } = null!;

        public GetRegistryInvokeArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetRegistryResult
    {
        /// <summary>
        /// Compartment Identifier
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        /// <summary>
        /// Registry description
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// Data Connectivity Management Registry display name, registries can be renamed
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// Unique identifier that is immutable on creation
        /// </summary>
        public readonly string Id;
        public readonly string RegistryId;
        /// <summary>
        /// Lifecycle states for registries in Data Connectivity Management Service CREATING - The resource is being created and may not be usable until the entire metadata is defined UPDATING - The resource is being updated and may not be usable until all changes are commited DELETING - The resource is being deleted and might require deep cleanup of children. ACTIVE   - The resource is valid and available for access INACTIVE - The resource might be incomplete in its definition or might have been made unavailable for administrative reasons DELETED  - The resource has been deleted and isn't available FAILED   - The resource is in a failed state due to validation or other errors
        /// </summary>
        public readonly string State;
        /// <summary>
        /// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        public readonly string StateMessage;
        /// <summary>
        /// The time the Data Connectivity Management Registry was created. An RFC3339 formatted datetime string
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The time the Data Connectivity Management Registry was updated. An RFC3339 formatted datetime string
        /// </summary>
        public readonly string TimeUpdated;
        /// <summary>
        /// Name of the user who updated the DCMS Registry.
        /// </summary>
        public readonly string UpdatedBy;

        [OutputConstructor]
        private GetRegistryResult(
            string compartmentId,

            ImmutableDictionary<string, object> definedTags,

            string description,

            string displayName,

            ImmutableDictionary<string, object> freeformTags,

            string id,

            string registryId,

            string state,

            string stateMessage,

            string timeCreated,

            string timeUpdated,

            string updatedBy)
        {
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            Description = description;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            RegistryId = registryId;
            State = state;
            StateMessage = stateMessage;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
            UpdatedBy = updatedBy;
        }
    }
}
