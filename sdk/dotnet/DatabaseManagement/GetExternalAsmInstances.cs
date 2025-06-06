// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseManagement
{
    public static class GetExternalAsmInstances
    {
        /// <summary>
        /// This data source provides the list of External Asm Instances in Oracle Cloud Infrastructure Database Management service.
        /// 
        /// Lists the ASM instances in the specified external ASM.
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
        ///     var testExternalAsmInstances = Oci.DatabaseManagement.GetExternalAsmInstances.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         DisplayName = externalAsmInstanceDisplayName,
        ///         ExternalAsmId = testExternalAsm.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetExternalAsmInstancesResult> InvokeAsync(GetExternalAsmInstancesArgs? args = null, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetExternalAsmInstancesResult>("oci:DatabaseManagement/getExternalAsmInstances:getExternalAsmInstances", args ?? new GetExternalAsmInstancesArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of External Asm Instances in Oracle Cloud Infrastructure Database Management service.
        /// 
        /// Lists the ASM instances in the specified external ASM.
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
        ///     var testExternalAsmInstances = Oci.DatabaseManagement.GetExternalAsmInstances.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         DisplayName = externalAsmInstanceDisplayName,
        ///         ExternalAsmId = testExternalAsm.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetExternalAsmInstancesResult> Invoke(GetExternalAsmInstancesInvokeArgs? args = null, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetExternalAsmInstancesResult>("oci:DatabaseManagement/getExternalAsmInstances:getExternalAsmInstances", args ?? new GetExternalAsmInstancesInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of External Asm Instances in Oracle Cloud Infrastructure Database Management service.
        /// 
        /// Lists the ASM instances in the specified external ASM.
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
        ///     var testExternalAsmInstances = Oci.DatabaseManagement.GetExternalAsmInstances.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         DisplayName = externalAsmInstanceDisplayName,
        ///         ExternalAsmId = testExternalAsm.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetExternalAsmInstancesResult> Invoke(GetExternalAsmInstancesInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetExternalAsmInstancesResult>("oci:DatabaseManagement/getExternalAsmInstances:getExternalAsmInstances", args ?? new GetExternalAsmInstancesInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetExternalAsmInstancesArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId")]
        public string? CompartmentId { get; set; }

        /// <summary>
        /// A filter to only return the resources that match the entire display name.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external ASM.
        /// </summary>
        [Input("externalAsmId")]
        public string? ExternalAsmId { get; set; }

        [Input("filters")]
        private List<Inputs.GetExternalAsmInstancesFilterArgs>? _filters;
        public List<Inputs.GetExternalAsmInstancesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetExternalAsmInstancesFilterArgs>());
            set => _filters = value;
        }

        public GetExternalAsmInstancesArgs()
        {
        }
        public static new GetExternalAsmInstancesArgs Empty => new GetExternalAsmInstancesArgs();
    }

    public sealed class GetExternalAsmInstancesInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        /// <summary>
        /// A filter to only return the resources that match the entire display name.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external ASM.
        /// </summary>
        [Input("externalAsmId")]
        public Input<string>? ExternalAsmId { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetExternalAsmInstancesFilterInputArgs>? _filters;
        public InputList<Inputs.GetExternalAsmInstancesFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetExternalAsmInstancesFilterInputArgs>());
            set => _filters = value;
        }

        public GetExternalAsmInstancesInvokeArgs()
        {
        }
        public static new GetExternalAsmInstancesInvokeArgs Empty => new GetExternalAsmInstancesInvokeArgs();
    }


    [OutputType]
    public sealed class GetExternalAsmInstancesResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        public readonly string? CompartmentId;
        /// <summary>
        /// The user-friendly name for the ASM instance. The name does not have to be unique.
        /// </summary>
        public readonly string? DisplayName;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external ASM that the ASM instance belongs to.
        /// </summary>
        public readonly string? ExternalAsmId;
        /// <summary>
        /// The list of external_asm_instance_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetExternalAsmInstancesExternalAsmInstanceCollectionResult> ExternalAsmInstanceCollections;
        public readonly ImmutableArray<Outputs.GetExternalAsmInstancesFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;

        [OutputConstructor]
        private GetExternalAsmInstancesResult(
            string? compartmentId,

            string? displayName,

            string? externalAsmId,

            ImmutableArray<Outputs.GetExternalAsmInstancesExternalAsmInstanceCollectionResult> externalAsmInstanceCollections,

            ImmutableArray<Outputs.GetExternalAsmInstancesFilterResult> filters,

            string id)
        {
            CompartmentId = compartmentId;
            DisplayName = displayName;
            ExternalAsmId = externalAsmId;
            ExternalAsmInstanceCollections = externalAsmInstanceCollections;
            Filters = filters;
            Id = id;
        }
    }
}
