// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core
{
    public static class GetByoipRanges
    {
        /// <summary>
        /// This data source provides the list of Byoip Ranges in Oracle Cloud Infrastructure Core service.
        /// 
        /// Lists the `ByoipRange` resources in the specified compartment.
        /// You can filter the list using query parameters.
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
        ///     var testByoipRanges = Oci.Core.GetByoipRanges.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         DisplayName = byoipRangeDisplayName,
        ///         State = byoipRangeState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetByoipRangesResult> InvokeAsync(GetByoipRangesArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetByoipRangesResult>("oci:Core/getByoipRanges:getByoipRanges", args ?? new GetByoipRangesArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Byoip Ranges in Oracle Cloud Infrastructure Core service.
        /// 
        /// Lists the `ByoipRange` resources in the specified compartment.
        /// You can filter the list using query parameters.
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
        ///     var testByoipRanges = Oci.Core.GetByoipRanges.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         DisplayName = byoipRangeDisplayName,
        ///         State = byoipRangeState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetByoipRangesResult> Invoke(GetByoipRangesInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetByoipRangesResult>("oci:Core/getByoipRanges:getByoipRanges", args ?? new GetByoipRangesInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Byoip Ranges in Oracle Cloud Infrastructure Core service.
        /// 
        /// Lists the `ByoipRange` resources in the specified compartment.
        /// You can filter the list using query parameters.
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
        ///     var testByoipRanges = Oci.Core.GetByoipRanges.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         DisplayName = byoipRangeDisplayName,
        ///         State = byoipRangeState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetByoipRangesResult> Invoke(GetByoipRangesInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetByoipRangesResult>("oci:Core/getByoipRanges:getByoipRanges", args ?? new GetByoipRangesInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetByoipRangesArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// A filter to return only resources that match the given display name exactly.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetByoipRangesFilterArgs>? _filters;
        public List<Inputs.GetByoipRangesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetByoipRangesFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only resources that match the given lifecycle state name exactly.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        public GetByoipRangesArgs()
        {
        }
        public static new GetByoipRangesArgs Empty => new GetByoipRangesArgs();
    }

    public sealed class GetByoipRangesInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// A filter to return only resources that match the given display name exactly.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetByoipRangesFilterInputArgs>? _filters;
        public InputList<Inputs.GetByoipRangesFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetByoipRangesFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only resources that match the given lifecycle state name exactly.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        public GetByoipRangesInvokeArgs()
        {
        }
        public static new GetByoipRangesInvokeArgs Empty => new GetByoipRangesInvokeArgs();
    }


    [OutputType]
    public sealed class GetByoipRangesResult
    {
        /// <summary>
        /// The list of byoip_range_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetByoipRangesByoipRangeCollectionResult> ByoipRangeCollections;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the BYOIP CIDR block.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetByoipRangesFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The `ByoipRange` resource's current state.
        /// </summary>
        public readonly string? State;

        [OutputConstructor]
        private GetByoipRangesResult(
            ImmutableArray<Outputs.GetByoipRangesByoipRangeCollectionResult> byoipRangeCollections,

            string compartmentId,

            string? displayName,

            ImmutableArray<Outputs.GetByoipRangesFilterResult> filters,

            string id,

            string? state)
        {
            ByoipRangeCollections = byoipRangeCollections;
            CompartmentId = compartmentId;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            State = state;
        }
    }
}
