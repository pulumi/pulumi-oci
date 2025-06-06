// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core
{
    public static class GetClusterNetworks
    {
        /// <summary>
        /// This data source provides the list of Cluster Networks in Oracle Cloud Infrastructure Core service.
        /// 
        /// Lists the [cluster networks with instance pools](https://docs.cloud.oracle.com/iaas/Content/Compute/Tasks/managingclusternetworks.htm)
        /// in the specified compartment.
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
        ///     var testClusterNetworks = Oci.Core.GetClusterNetworks.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         DisplayName = clusterNetworkDisplayName,
        ///         State = clusterNetworkState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetClusterNetworksResult> InvokeAsync(GetClusterNetworksArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetClusterNetworksResult>("oci:Core/getClusterNetworks:getClusterNetworks", args ?? new GetClusterNetworksArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Cluster Networks in Oracle Cloud Infrastructure Core service.
        /// 
        /// Lists the [cluster networks with instance pools](https://docs.cloud.oracle.com/iaas/Content/Compute/Tasks/managingclusternetworks.htm)
        /// in the specified compartment.
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
        ///     var testClusterNetworks = Oci.Core.GetClusterNetworks.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         DisplayName = clusterNetworkDisplayName,
        ///         State = clusterNetworkState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetClusterNetworksResult> Invoke(GetClusterNetworksInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetClusterNetworksResult>("oci:Core/getClusterNetworks:getClusterNetworks", args ?? new GetClusterNetworksInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Cluster Networks in Oracle Cloud Infrastructure Core service.
        /// 
        /// Lists the [cluster networks with instance pools](https://docs.cloud.oracle.com/iaas/Content/Compute/Tasks/managingclusternetworks.htm)
        /// in the specified compartment.
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
        ///     var testClusterNetworks = Oci.Core.GetClusterNetworks.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         DisplayName = clusterNetworkDisplayName,
        ///         State = clusterNetworkState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetClusterNetworksResult> Invoke(GetClusterNetworksInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetClusterNetworksResult>("oci:Core/getClusterNetworks:getClusterNetworks", args ?? new GetClusterNetworksInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetClusterNetworksArgs : global::Pulumi.InvokeArgs
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
        private List<Inputs.GetClusterNetworksFilterArgs>? _filters;
        public List<Inputs.GetClusterNetworksFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetClusterNetworksFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to only return resources that match the given lifecycle state. The state value is case-insensitive.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        public GetClusterNetworksArgs()
        {
        }
        public static new GetClusterNetworksArgs Empty => new GetClusterNetworksArgs();
    }

    public sealed class GetClusterNetworksInvokeArgs : global::Pulumi.InvokeArgs
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
        private InputList<Inputs.GetClusterNetworksFilterInputArgs>? _filters;
        public InputList<Inputs.GetClusterNetworksFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetClusterNetworksFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to only return resources that match the given lifecycle state. The state value is case-insensitive.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        public GetClusterNetworksInvokeArgs()
        {
        }
        public static new GetClusterNetworksInvokeArgs Empty => new GetClusterNetworksInvokeArgs();
    }


    [OutputType]
    public sealed class GetClusterNetworksResult
    {
        /// <summary>
        /// The list of cluster_networks.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetClusterNetworksClusterNetworkResult> ClusterNetworks;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the instance pool.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The display name of the VNIC. This is also used to match against the instance configuration defined secondary VNIC.
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetClusterNetworksFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The current state of the cluster network.
        /// </summary>
        public readonly string? State;

        [OutputConstructor]
        private GetClusterNetworksResult(
            ImmutableArray<Outputs.GetClusterNetworksClusterNetworkResult> clusterNetworks,

            string compartmentId,

            string? displayName,

            ImmutableArray<Outputs.GetClusterNetworksFilterResult> filters,

            string id,

            string? state)
        {
            ClusterNetworks = clusterNetworks;
            CompartmentId = compartmentId;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            State = state;
        }
    }
}
