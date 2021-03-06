// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core
{
    public static class GetPeerRegionForRemotePeerings
    {
        /// <summary>
        /// This data source provides the list of Peer Region For Remote Peerings in Oracle Cloud Infrastructure Core service.
        /// 
        /// Lists the regions that support remote VCN peering (which is peering across regions).
        /// For more information, see [VCN Peering](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/VCNpeering.htm).
        /// 
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
        ///         var testPeerRegionForRemotePeerings = Output.Create(Oci.Core.GetPeerRegionForRemotePeerings.InvokeAsync());
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetPeerRegionForRemotePeeringsResult> InvokeAsync(GetPeerRegionForRemotePeeringsArgs? args = null, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetPeerRegionForRemotePeeringsResult>("oci:Core/getPeerRegionForRemotePeerings:getPeerRegionForRemotePeerings", args ?? new GetPeerRegionForRemotePeeringsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Peer Region For Remote Peerings in Oracle Cloud Infrastructure Core service.
        /// 
        /// Lists the regions that support remote VCN peering (which is peering across regions).
        /// For more information, see [VCN Peering](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/VCNpeering.htm).
        /// 
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
        ///         var testPeerRegionForRemotePeerings = Output.Create(Oci.Core.GetPeerRegionForRemotePeerings.InvokeAsync());
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetPeerRegionForRemotePeeringsResult> Invoke(GetPeerRegionForRemotePeeringsInvokeArgs? args = null, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetPeerRegionForRemotePeeringsResult>("oci:Core/getPeerRegionForRemotePeerings:getPeerRegionForRemotePeerings", args ?? new GetPeerRegionForRemotePeeringsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetPeerRegionForRemotePeeringsArgs : Pulumi.InvokeArgs
    {
        [Input("filters")]
        private List<Inputs.GetPeerRegionForRemotePeeringsFilterArgs>? _filters;
        public List<Inputs.GetPeerRegionForRemotePeeringsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetPeerRegionForRemotePeeringsFilterArgs>());
            set => _filters = value;
        }

        public GetPeerRegionForRemotePeeringsArgs()
        {
        }
    }

    public sealed class GetPeerRegionForRemotePeeringsInvokeArgs : Pulumi.InvokeArgs
    {
        [Input("filters")]
        private InputList<Inputs.GetPeerRegionForRemotePeeringsFilterInputArgs>? _filters;
        public InputList<Inputs.GetPeerRegionForRemotePeeringsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetPeerRegionForRemotePeeringsFilterInputArgs>());
            set => _filters = value;
        }

        public GetPeerRegionForRemotePeeringsInvokeArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetPeerRegionForRemotePeeringsResult
    {
        public readonly ImmutableArray<Outputs.GetPeerRegionForRemotePeeringsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The list of peer_region_for_remote_peerings.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetPeerRegionForRemotePeeringsPeerRegionForRemotePeeringResult> PeerRegionForRemotePeerings;

        [OutputConstructor]
        private GetPeerRegionForRemotePeeringsResult(
            ImmutableArray<Outputs.GetPeerRegionForRemotePeeringsFilterResult> filters,

            string id,

            ImmutableArray<Outputs.GetPeerRegionForRemotePeeringsPeerRegionForRemotePeeringResult> peerRegionForRemotePeerings)
        {
            Filters = filters;
            Id = id;
            PeerRegionForRemotePeerings = peerRegionForRemotePeerings;
        }
    }
}
