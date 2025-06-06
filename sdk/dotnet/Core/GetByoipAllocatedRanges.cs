// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core
{
    public static class GetByoipAllocatedRanges
    {
        /// <summary>
        /// This data source provides the list of Byoip Allocated Ranges in Oracle Cloud Infrastructure Core service.
        /// 
        /// Lists the subranges of a BYOIP CIDR block currently allocated to an IP pool.
        /// Each `ByoipAllocatedRange` object also lists the IP pool where it is allocated.
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
        ///     var testByoipAllocatedRanges = Oci.Core.GetByoipAllocatedRanges.Invoke(new()
        ///     {
        ///         ByoipRangeId = testByoipRange.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetByoipAllocatedRangesResult> InvokeAsync(GetByoipAllocatedRangesArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetByoipAllocatedRangesResult>("oci:Core/getByoipAllocatedRanges:getByoipAllocatedRanges", args ?? new GetByoipAllocatedRangesArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Byoip Allocated Ranges in Oracle Cloud Infrastructure Core service.
        /// 
        /// Lists the subranges of a BYOIP CIDR block currently allocated to an IP pool.
        /// Each `ByoipAllocatedRange` object also lists the IP pool where it is allocated.
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
        ///     var testByoipAllocatedRanges = Oci.Core.GetByoipAllocatedRanges.Invoke(new()
        ///     {
        ///         ByoipRangeId = testByoipRange.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetByoipAllocatedRangesResult> Invoke(GetByoipAllocatedRangesInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetByoipAllocatedRangesResult>("oci:Core/getByoipAllocatedRanges:getByoipAllocatedRanges", args ?? new GetByoipAllocatedRangesInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Byoip Allocated Ranges in Oracle Cloud Infrastructure Core service.
        /// 
        /// Lists the subranges of a BYOIP CIDR block currently allocated to an IP pool.
        /// Each `ByoipAllocatedRange` object also lists the IP pool where it is allocated.
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
        ///     var testByoipAllocatedRanges = Oci.Core.GetByoipAllocatedRanges.Invoke(new()
        ///     {
        ///         ByoipRangeId = testByoipRange.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetByoipAllocatedRangesResult> Invoke(GetByoipAllocatedRangesInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetByoipAllocatedRangesResult>("oci:Core/getByoipAllocatedRanges:getByoipAllocatedRanges", args ?? new GetByoipAllocatedRangesInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetByoipAllocatedRangesArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the `ByoipRange` resource containing the BYOIP CIDR block.
        /// </summary>
        [Input("byoipRangeId", required: true)]
        public string ByoipRangeId { get; set; } = null!;

        [Input("filters")]
        private List<Inputs.GetByoipAllocatedRangesFilterArgs>? _filters;
        public List<Inputs.GetByoipAllocatedRangesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetByoipAllocatedRangesFilterArgs>());
            set => _filters = value;
        }

        public GetByoipAllocatedRangesArgs()
        {
        }
        public static new GetByoipAllocatedRangesArgs Empty => new GetByoipAllocatedRangesArgs();
    }

    public sealed class GetByoipAllocatedRangesInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the `ByoipRange` resource containing the BYOIP CIDR block.
        /// </summary>
        [Input("byoipRangeId", required: true)]
        public Input<string> ByoipRangeId { get; set; } = null!;

        [Input("filters")]
        private InputList<Inputs.GetByoipAllocatedRangesFilterInputArgs>? _filters;
        public InputList<Inputs.GetByoipAllocatedRangesFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetByoipAllocatedRangesFilterInputArgs>());
            set => _filters = value;
        }

        public GetByoipAllocatedRangesInvokeArgs()
        {
        }
        public static new GetByoipAllocatedRangesInvokeArgs Empty => new GetByoipAllocatedRangesInvokeArgs();
    }


    [OutputType]
    public sealed class GetByoipAllocatedRangesResult
    {
        /// <summary>
        /// The list of byoip_allocated_range_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetByoipAllocatedRangesByoipAllocatedRangeCollectionResult> ByoipAllocatedRangeCollections;
        public readonly string ByoipRangeId;
        public readonly ImmutableArray<Outputs.GetByoipAllocatedRangesFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;

        [OutputConstructor]
        private GetByoipAllocatedRangesResult(
            ImmutableArray<Outputs.GetByoipAllocatedRangesByoipAllocatedRangeCollectionResult> byoipAllocatedRangeCollections,

            string byoipRangeId,

            ImmutableArray<Outputs.GetByoipAllocatedRangesFilterResult> filters,

            string id)
        {
            ByoipAllocatedRangeCollections = byoipAllocatedRangeCollections;
            ByoipRangeId = byoipRangeId;
            Filters = filters;
            Id = id;
        }
    }
}
