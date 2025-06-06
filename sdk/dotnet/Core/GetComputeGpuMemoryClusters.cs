// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core
{
    public static class GetComputeGpuMemoryClusters
    {
        /// <summary>
        /// This data source provides the list of Compute Gpu Memory Clusters in Oracle Cloud Infrastructure Core service.
        /// 
        /// List all of the compute GPU memory clusters.
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
        ///     var testComputeGpuMemoryClusters = Oci.Core.GetComputeGpuMemoryClusters.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         AvailabilityDomain = computeGpuMemoryClusterAvailabilityDomain,
        ///         ComputeClusterId = testComputeCluster.Id,
        ///         ComputeGpuMemoryClusterId = testComputeGpuMemoryCluster.Id,
        ///         DisplayName = computeGpuMemoryClusterDisplayName,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetComputeGpuMemoryClustersResult> InvokeAsync(GetComputeGpuMemoryClustersArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetComputeGpuMemoryClustersResult>("oci:Core/getComputeGpuMemoryClusters:getComputeGpuMemoryClusters", args ?? new GetComputeGpuMemoryClustersArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Compute Gpu Memory Clusters in Oracle Cloud Infrastructure Core service.
        /// 
        /// List all of the compute GPU memory clusters.
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
        ///     var testComputeGpuMemoryClusters = Oci.Core.GetComputeGpuMemoryClusters.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         AvailabilityDomain = computeGpuMemoryClusterAvailabilityDomain,
        ///         ComputeClusterId = testComputeCluster.Id,
        ///         ComputeGpuMemoryClusterId = testComputeGpuMemoryCluster.Id,
        ///         DisplayName = computeGpuMemoryClusterDisplayName,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetComputeGpuMemoryClustersResult> Invoke(GetComputeGpuMemoryClustersInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetComputeGpuMemoryClustersResult>("oci:Core/getComputeGpuMemoryClusters:getComputeGpuMemoryClusters", args ?? new GetComputeGpuMemoryClustersInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Compute Gpu Memory Clusters in Oracle Cloud Infrastructure Core service.
        /// 
        /// List all of the compute GPU memory clusters.
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
        ///     var testComputeGpuMemoryClusters = Oci.Core.GetComputeGpuMemoryClusters.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         AvailabilityDomain = computeGpuMemoryClusterAvailabilityDomain,
        ///         ComputeClusterId = testComputeCluster.Id,
        ///         ComputeGpuMemoryClusterId = testComputeGpuMemoryCluster.Id,
        ///         DisplayName = computeGpuMemoryClusterDisplayName,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetComputeGpuMemoryClustersResult> Invoke(GetComputeGpuMemoryClustersInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetComputeGpuMemoryClustersResult>("oci:Core/getComputeGpuMemoryClusters:getComputeGpuMemoryClusters", args ?? new GetComputeGpuMemoryClustersInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetComputeGpuMemoryClustersArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The name of the availability domain.  Example: `Uocm:PHX-AD-1`
        /// </summary>
        [Input("availabilityDomain")]
        public string? AvailabilityDomain { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compute cluster. A [compute cluster](https://docs.cloud.oracle.com/iaas/Content/Compute/Tasks/compute-clusters.htm) is a remote direct memory access (RDMA) network group.
        /// </summary>
        [Input("computeClusterId")]
        public string? ComputeClusterId { get; set; }

        /// <summary>
        /// A filter to return only the listings that matches the given GPU memory cluster id.
        /// </summary>
        [Input("computeGpuMemoryClusterId")]
        public string? ComputeGpuMemoryClusterId { get; set; }

        /// <summary>
        /// A filter to return only resources that match the given display name exactly.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetComputeGpuMemoryClustersFilterArgs>? _filters;
        public List<Inputs.GetComputeGpuMemoryClustersFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetComputeGpuMemoryClustersFilterArgs>());
            set => _filters = value;
        }

        public GetComputeGpuMemoryClustersArgs()
        {
        }
        public static new GetComputeGpuMemoryClustersArgs Empty => new GetComputeGpuMemoryClustersArgs();
    }

    public sealed class GetComputeGpuMemoryClustersInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The name of the availability domain.  Example: `Uocm:PHX-AD-1`
        /// </summary>
        [Input("availabilityDomain")]
        public Input<string>? AvailabilityDomain { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compute cluster. A [compute cluster](https://docs.cloud.oracle.com/iaas/Content/Compute/Tasks/compute-clusters.htm) is a remote direct memory access (RDMA) network group.
        /// </summary>
        [Input("computeClusterId")]
        public Input<string>? ComputeClusterId { get; set; }

        /// <summary>
        /// A filter to return only the listings that matches the given GPU memory cluster id.
        /// </summary>
        [Input("computeGpuMemoryClusterId")]
        public Input<string>? ComputeGpuMemoryClusterId { get; set; }

        /// <summary>
        /// A filter to return only resources that match the given display name exactly.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetComputeGpuMemoryClustersFilterInputArgs>? _filters;
        public InputList<Inputs.GetComputeGpuMemoryClustersFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetComputeGpuMemoryClustersFilterInputArgs>());
            set => _filters = value;
        }

        public GetComputeGpuMemoryClustersInvokeArgs()
        {
        }
        public static new GetComputeGpuMemoryClustersInvokeArgs Empty => new GetComputeGpuMemoryClustersInvokeArgs();
    }


    [OutputType]
    public sealed class GetComputeGpuMemoryClustersResult
    {
        /// <summary>
        /// The availability domain of the GPU memory cluster.
        /// </summary>
        public readonly string? AvailabilityDomain;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the compute GPU memory cluster.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compute cluster.
        /// </summary>
        public readonly string? ComputeClusterId;
        /// <summary>
        /// The list of compute_gpu_memory_cluster_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetComputeGpuMemoryClustersComputeGpuMemoryClusterCollectionResult> ComputeGpuMemoryClusterCollections;
        public readonly string? ComputeGpuMemoryClusterId;
        /// <summary>
        /// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetComputeGpuMemoryClustersFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;

        [OutputConstructor]
        private GetComputeGpuMemoryClustersResult(
            string? availabilityDomain,

            string compartmentId,

            string? computeClusterId,

            ImmutableArray<Outputs.GetComputeGpuMemoryClustersComputeGpuMemoryClusterCollectionResult> computeGpuMemoryClusterCollections,

            string? computeGpuMemoryClusterId,

            string? displayName,

            ImmutableArray<Outputs.GetComputeGpuMemoryClustersFilterResult> filters,

            string id)
        {
            AvailabilityDomain = availabilityDomain;
            CompartmentId = compartmentId;
            ComputeClusterId = computeClusterId;
            ComputeGpuMemoryClusterCollections = computeGpuMemoryClusterCollections;
            ComputeGpuMemoryClusterId = computeGpuMemoryClusterId;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
        }
    }
}
