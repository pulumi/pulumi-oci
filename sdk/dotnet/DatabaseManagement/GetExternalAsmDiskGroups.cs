// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseManagement
{
    public static class GetExternalAsmDiskGroups
    {
        /// <summary>
        /// This data source provides the list of External Asm Disk Groups in Oracle Cloud Infrastructure Database Management service.
        /// 
        /// Lists ASM disk groups for the external ASM specified by `externalAsmId`.
        /// 
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testExternalAsmDiskGroups = Oci.DatabaseManagement.GetExternalAsmDiskGroups.Invoke(new()
        ///     {
        ///         ExternalAsmId = oci_database_management_external_asm.Test_external_asm.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetExternalAsmDiskGroupsResult> InvokeAsync(GetExternalAsmDiskGroupsArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetExternalAsmDiskGroupsResult>("oci:DatabaseManagement/getExternalAsmDiskGroups:getExternalAsmDiskGroups", args ?? new GetExternalAsmDiskGroupsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of External Asm Disk Groups in Oracle Cloud Infrastructure Database Management service.
        /// 
        /// Lists ASM disk groups for the external ASM specified by `externalAsmId`.
        /// 
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testExternalAsmDiskGroups = Oci.DatabaseManagement.GetExternalAsmDiskGroups.Invoke(new()
        ///     {
        ///         ExternalAsmId = oci_database_management_external_asm.Test_external_asm.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetExternalAsmDiskGroupsResult> Invoke(GetExternalAsmDiskGroupsInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetExternalAsmDiskGroupsResult>("oci:DatabaseManagement/getExternalAsmDiskGroups:getExternalAsmDiskGroups", args ?? new GetExternalAsmDiskGroupsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetExternalAsmDiskGroupsArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external ASM.
        /// </summary>
        [Input("externalAsmId", required: true)]
        public string ExternalAsmId { get; set; } = null!;

        [Input("filters")]
        private List<Inputs.GetExternalAsmDiskGroupsFilterArgs>? _filters;
        public List<Inputs.GetExternalAsmDiskGroupsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetExternalAsmDiskGroupsFilterArgs>());
            set => _filters = value;
        }

        public GetExternalAsmDiskGroupsArgs()
        {
        }
        public static new GetExternalAsmDiskGroupsArgs Empty => new GetExternalAsmDiskGroupsArgs();
    }

    public sealed class GetExternalAsmDiskGroupsInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external ASM.
        /// </summary>
        [Input("externalAsmId", required: true)]
        public Input<string> ExternalAsmId { get; set; } = null!;

        [Input("filters")]
        private InputList<Inputs.GetExternalAsmDiskGroupsFilterInputArgs>? _filters;
        public InputList<Inputs.GetExternalAsmDiskGroupsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetExternalAsmDiskGroupsFilterInputArgs>());
            set => _filters = value;
        }

        public GetExternalAsmDiskGroupsInvokeArgs()
        {
        }
        public static new GetExternalAsmDiskGroupsInvokeArgs Empty => new GetExternalAsmDiskGroupsInvokeArgs();
    }


    [OutputType]
    public sealed class GetExternalAsmDiskGroupsResult
    {
        /// <summary>
        /// The list of external_asm_disk_group_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetExternalAsmDiskGroupsExternalAsmDiskGroupCollectionResult> ExternalAsmDiskGroupCollections;
        public readonly string ExternalAsmId;
        public readonly ImmutableArray<Outputs.GetExternalAsmDiskGroupsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;

        [OutputConstructor]
        private GetExternalAsmDiskGroupsResult(
            ImmutableArray<Outputs.GetExternalAsmDiskGroupsExternalAsmDiskGroupCollectionResult> externalAsmDiskGroupCollections,

            string externalAsmId,

            ImmutableArray<Outputs.GetExternalAsmDiskGroupsFilterResult> filters,

            string id)
        {
            ExternalAsmDiskGroupCollections = externalAsmDiskGroupCollections;
            ExternalAsmId = externalAsmId;
            Filters = filters;
            Id = id;
        }
    }
}