// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core
{
    public static class GetComputeClusters
    {
        /// <summary>
        /// This data source provides the list of Compute Clusters in Oracle Cloud Infrastructure Core service.
        /// 
        /// Lists the compute clusters in the specified compartment.
        /// A [compute cluster](https://docs.cloud.oracle.com/iaas/Content/Compute/Tasks/compute-clusters.htm) is a remote direct memory access (RDMA) network group.
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
        ///     var testComputeClusters = Oci.Core.GetComputeClusters.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         AvailabilityDomain = computeClusterAvailabilityDomain,
        ///         DisplayName = computeClusterDisplayName,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetComputeClustersResult> InvokeAsync(GetComputeClustersArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetComputeClustersResult>("oci:Core/getComputeClusters:getComputeClusters", args ?? new GetComputeClustersArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Compute Clusters in Oracle Cloud Infrastructure Core service.
        /// 
        /// Lists the compute clusters in the specified compartment.
        /// A [compute cluster](https://docs.cloud.oracle.com/iaas/Content/Compute/Tasks/compute-clusters.htm) is a remote direct memory access (RDMA) network group.
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
        ///     var testComputeClusters = Oci.Core.GetComputeClusters.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         AvailabilityDomain = computeClusterAvailabilityDomain,
        ///         DisplayName = computeClusterDisplayName,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetComputeClustersResult> Invoke(GetComputeClustersInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetComputeClustersResult>("oci:Core/getComputeClusters:getComputeClusters", args ?? new GetComputeClustersInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Compute Clusters in Oracle Cloud Infrastructure Core service.
        /// 
        /// Lists the compute clusters in the specified compartment.
        /// A [compute cluster](https://docs.cloud.oracle.com/iaas/Content/Compute/Tasks/compute-clusters.htm) is a remote direct memory access (RDMA) network group.
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
        ///     var testComputeClusters = Oci.Core.GetComputeClusters.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         AvailabilityDomain = computeClusterAvailabilityDomain,
        ///         DisplayName = computeClusterDisplayName,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetComputeClustersResult> Invoke(GetComputeClustersInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetComputeClustersResult>("oci:Core/getComputeClusters:getComputeClusters", args ?? new GetComputeClustersInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetComputeClustersArgs : global::Pulumi.InvokeArgs
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
        /// A filter to return only resources that match the given display name exactly.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetComputeClustersFilterArgs>? _filters;
        public List<Inputs.GetComputeClustersFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetComputeClustersFilterArgs>());
            set => _filters = value;
        }

        public GetComputeClustersArgs()
        {
        }
        public static new GetComputeClustersArgs Empty => new GetComputeClustersArgs();
    }

    public sealed class GetComputeClustersInvokeArgs : global::Pulumi.InvokeArgs
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
        /// A filter to return only resources that match the given display name exactly.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetComputeClustersFilterInputArgs>? _filters;
        public InputList<Inputs.GetComputeClustersFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetComputeClustersFilterInputArgs>());
            set => _filters = value;
        }

        public GetComputeClustersInvokeArgs()
        {
        }
        public static new GetComputeClustersInvokeArgs Empty => new GetComputeClustersInvokeArgs();
    }


    [OutputType]
    public sealed class GetComputeClustersResult
    {
        /// <summary>
        /// The availability domain the compute cluster is running in.  Example: `Uocm:PHX-AD-1`
        /// </summary>
        public readonly string? AvailabilityDomain;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the compute cluster.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The list of compute_cluster_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetComputeClustersComputeClusterCollectionResult> ComputeClusterCollections;
        /// <summary>
        /// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetComputeClustersFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;

        [OutputConstructor]
        private GetComputeClustersResult(
            string? availabilityDomain,

            string compartmentId,

            ImmutableArray<Outputs.GetComputeClustersComputeClusterCollectionResult> computeClusterCollections,

            string? displayName,

            ImmutableArray<Outputs.GetComputeClustersFilterResult> filters,

            string id)
        {
            AvailabilityDomain = availabilityDomain;
            CompartmentId = compartmentId;
            ComputeClusterCollections = computeClusterCollections;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
        }
    }
}
