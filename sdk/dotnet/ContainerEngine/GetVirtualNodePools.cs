// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ContainerEngine
{
    public static class GetVirtualNodePools
    {
        /// <summary>
        /// This data source provides the list of Virtual Node Pools in Oracle Cloud Infrastructure Container Engine service.
        /// 
        /// List all the virtual node pools in a compartment, and optionally filter by cluster.
        /// </summary>
        public static Task<GetVirtualNodePoolsResult> InvokeAsync(GetVirtualNodePoolsArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetVirtualNodePoolsResult>("oci:ContainerEngine/getVirtualNodePools:getVirtualNodePools", args ?? new GetVirtualNodePoolsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Virtual Node Pools in Oracle Cloud Infrastructure Container Engine service.
        /// 
        /// List all the virtual node pools in a compartment, and optionally filter by cluster.
        /// </summary>
        public static Output<GetVirtualNodePoolsResult> Invoke(GetVirtualNodePoolsInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetVirtualNodePoolsResult>("oci:ContainerEngine/getVirtualNodePools:getVirtualNodePools", args ?? new GetVirtualNodePoolsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetVirtualNodePoolsArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the cluster.
        /// </summary>
        [Input("clusterId")]
        public string? ClusterId { get; set; }

        /// <summary>
        /// The OCID of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// Display name of the virtual node pool. This is a non-unique value.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetVirtualNodePoolsFilterArgs>? _filters;
        public List<Inputs.GetVirtualNodePoolsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetVirtualNodePoolsFilterArgs>());
            set => _filters = value;
        }

        [Input("states")]
        private List<string>? _states;

        /// <summary>
        /// A virtual node pool lifecycle state to filter on. Can have multiple parameters of this name.
        /// </summary>
        public List<string> States
        {
            get => _states ?? (_states = new List<string>());
            set => _states = value;
        }

        public GetVirtualNodePoolsArgs()
        {
        }
        public static new GetVirtualNodePoolsArgs Empty => new GetVirtualNodePoolsArgs();
    }

    public sealed class GetVirtualNodePoolsInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the cluster.
        /// </summary>
        [Input("clusterId")]
        public Input<string>? ClusterId { get; set; }

        /// <summary>
        /// The OCID of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// Display name of the virtual node pool. This is a non-unique value.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetVirtualNodePoolsFilterInputArgs>? _filters;
        public InputList<Inputs.GetVirtualNodePoolsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetVirtualNodePoolsFilterInputArgs>());
            set => _filters = value;
        }

        [Input("states")]
        private InputList<string>? _states;

        /// <summary>
        /// A virtual node pool lifecycle state to filter on. Can have multiple parameters of this name.
        /// </summary>
        public InputList<string> States
        {
            get => _states ?? (_states = new InputList<string>());
            set => _states = value;
        }

        public GetVirtualNodePoolsInvokeArgs()
        {
        }
        public static new GetVirtualNodePoolsInvokeArgs Empty => new GetVirtualNodePoolsInvokeArgs();
    }


    [OutputType]
    public sealed class GetVirtualNodePoolsResult
    {
        /// <summary>
        /// The cluster the virtual node pool is associated with. A virtual node pool can only be associated with one cluster.
        /// </summary>
        public readonly string? ClusterId;
        /// <summary>
        /// Compartment of the virtual node pool.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Display name of the virtual node pool. This is a non-unique value.
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetVirtualNodePoolsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The state of the Virtual Node Pool.
        /// </summary>
        public readonly ImmutableArray<string> States;
        /// <summary>
        /// The list of virtual_node_pools.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetVirtualNodePoolsVirtualNodePoolResult> VirtualNodePools;

        [OutputConstructor]
        private GetVirtualNodePoolsResult(
            string? clusterId,

            string compartmentId,

            string? displayName,

            ImmutableArray<Outputs.GetVirtualNodePoolsFilterResult> filters,

            string id,

            ImmutableArray<string> states,

            ImmutableArray<Outputs.GetVirtualNodePoolsVirtualNodePoolResult> virtualNodePools)
        {
            ClusterId = clusterId;
            CompartmentId = compartmentId;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            States = states;
            VirtualNodePools = virtualNodePools;
        }
    }
}