// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.BigDataService
{
    public static class GetBdsInstanceListOsPatches
    {
        /// <summary>
        /// This data source provides the list of Bds Instance List Os Patches in Oracle Cloud Infrastructure Big Data Service service.
        /// 
        /// List all available os patches for a given cluster
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using System.Linq;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testBdsInstanceListOsPatches = Oci.BigDataService.GetBdsInstanceListOsPatches.Invoke(new()
        ///     {
        ///         BdsInstanceId = oci_bds_bds_instance.Test_bds_instance.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetBdsInstanceListOsPatchesResult> InvokeAsync(GetBdsInstanceListOsPatchesArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetBdsInstanceListOsPatchesResult>("oci:BigDataService/getBdsInstanceListOsPatches:getBdsInstanceListOsPatches", args ?? new GetBdsInstanceListOsPatchesArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Bds Instance List Os Patches in Oracle Cloud Infrastructure Big Data Service service.
        /// 
        /// List all available os patches for a given cluster
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using System.Linq;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testBdsInstanceListOsPatches = Oci.BigDataService.GetBdsInstanceListOsPatches.Invoke(new()
        ///     {
        ///         BdsInstanceId = oci_bds_bds_instance.Test_bds_instance.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetBdsInstanceListOsPatchesResult> Invoke(GetBdsInstanceListOsPatchesInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetBdsInstanceListOsPatchesResult>("oci:BigDataService/getBdsInstanceListOsPatches:getBdsInstanceListOsPatches", args ?? new GetBdsInstanceListOsPatchesInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetBdsInstanceListOsPatchesArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the cluster.
        /// </summary>
        [Input("bdsInstanceId", required: true)]
        public string BdsInstanceId { get; set; } = null!;

        [Input("filters")]
        private List<Inputs.GetBdsInstanceListOsPatchesFilterArgs>? _filters;
        public List<Inputs.GetBdsInstanceListOsPatchesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetBdsInstanceListOsPatchesFilterArgs>());
            set => _filters = value;
        }

        public GetBdsInstanceListOsPatchesArgs()
        {
        }
        public static new GetBdsInstanceListOsPatchesArgs Empty => new GetBdsInstanceListOsPatchesArgs();
    }

    public sealed class GetBdsInstanceListOsPatchesInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the cluster.
        /// </summary>
        [Input("bdsInstanceId", required: true)]
        public Input<string> BdsInstanceId { get; set; } = null!;

        [Input("filters")]
        private InputList<Inputs.GetBdsInstanceListOsPatchesFilterInputArgs>? _filters;
        public InputList<Inputs.GetBdsInstanceListOsPatchesFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetBdsInstanceListOsPatchesFilterInputArgs>());
            set => _filters = value;
        }

        public GetBdsInstanceListOsPatchesInvokeArgs()
        {
        }
        public static new GetBdsInstanceListOsPatchesInvokeArgs Empty => new GetBdsInstanceListOsPatchesInvokeArgs();
    }


    [OutputType]
    public sealed class GetBdsInstanceListOsPatchesResult
    {
        public readonly string BdsInstanceId;
        public readonly ImmutableArray<Outputs.GetBdsInstanceListOsPatchesFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The list of os_patches.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetBdsInstanceListOsPatchesOsPatchResult> OsPatches;

        [OutputConstructor]
        private GetBdsInstanceListOsPatchesResult(
            string bdsInstanceId,

            ImmutableArray<Outputs.GetBdsInstanceListOsPatchesFilterResult> filters,

            string id,

            ImmutableArray<Outputs.GetBdsInstanceListOsPatchesOsPatchResult> osPatches)
        {
            BdsInstanceId = bdsInstanceId;
            Filters = filters;
            Id = id;
            OsPatches = osPatches;
        }
    }
}