// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.GenerativeAi
{
    public static class GetDedicatedAiClusters
    {
        /// <summary>
        /// This data source provides the list of Dedicated Ai Clusters in Oracle Cloud Infrastructure Generative AI service.
        /// 
        /// Lists the dedicated AI clusters in a specific compartment.
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
        ///     var testDedicatedAiClusters = Oci.GenerativeAi.GetDedicatedAiClusters.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         DisplayName = dedicatedAiClusterDisplayName,
        ///         Id = dedicatedAiClusterId,
        ///         State = dedicatedAiClusterState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetDedicatedAiClustersResult> InvokeAsync(GetDedicatedAiClustersArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetDedicatedAiClustersResult>("oci:GenerativeAi/getDedicatedAiClusters:getDedicatedAiClusters", args ?? new GetDedicatedAiClustersArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Dedicated Ai Clusters in Oracle Cloud Infrastructure Generative AI service.
        /// 
        /// Lists the dedicated AI clusters in a specific compartment.
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
        ///     var testDedicatedAiClusters = Oci.GenerativeAi.GetDedicatedAiClusters.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         DisplayName = dedicatedAiClusterDisplayName,
        ///         Id = dedicatedAiClusterId,
        ///         State = dedicatedAiClusterState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetDedicatedAiClustersResult> Invoke(GetDedicatedAiClustersInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetDedicatedAiClustersResult>("oci:GenerativeAi/getDedicatedAiClusters:getDedicatedAiClusters", args ?? new GetDedicatedAiClustersInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Dedicated Ai Clusters in Oracle Cloud Infrastructure Generative AI service.
        /// 
        /// Lists the dedicated AI clusters in a specific compartment.
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
        ///     var testDedicatedAiClusters = Oci.GenerativeAi.GetDedicatedAiClusters.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         DisplayName = dedicatedAiClusterDisplayName,
        ///         Id = dedicatedAiClusterId,
        ///         State = dedicatedAiClusterState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetDedicatedAiClustersResult> Invoke(GetDedicatedAiClustersInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetDedicatedAiClustersResult>("oci:GenerativeAi/getDedicatedAiClusters:getDedicatedAiClusters", args ?? new GetDedicatedAiClustersInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetDedicatedAiClustersArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// A filter to return only resources that match the given display name exactly.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetDedicatedAiClustersFilterArgs>? _filters;
        public List<Inputs.GetDedicatedAiClustersFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetDedicatedAiClustersFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the dedicated AI cluster.
        /// </summary>
        [Input("id")]
        public string? Id { get; set; }

        /// <summary>
        /// A filter to return only the dedicated AI clusters that their lifecycle state matches the given lifecycle state.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        public GetDedicatedAiClustersArgs()
        {
        }
        public static new GetDedicatedAiClustersArgs Empty => new GetDedicatedAiClustersArgs();
    }

    public sealed class GetDedicatedAiClustersInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// A filter to return only resources that match the given display name exactly.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetDedicatedAiClustersFilterInputArgs>? _filters;
        public InputList<Inputs.GetDedicatedAiClustersFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetDedicatedAiClustersFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the dedicated AI cluster.
        /// </summary>
        [Input("id")]
        public Input<string>? Id { get; set; }

        /// <summary>
        /// A filter to return only the dedicated AI clusters that their lifecycle state matches the given lifecycle state.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        public GetDedicatedAiClustersInvokeArgs()
        {
        }
        public static new GetDedicatedAiClustersInvokeArgs Empty => new GetDedicatedAiClustersInvokeArgs();
    }


    [OutputType]
    public sealed class GetDedicatedAiClustersResult
    {
        public readonly string CompartmentId;
        /// <summary>
        /// The list of dedicated_ai_cluster_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDedicatedAiClustersDedicatedAiClusterCollectionResult> DedicatedAiClusterCollections;
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetDedicatedAiClustersFilterResult> Filters;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the dedicated AI cluster.
        /// </summary>
        public readonly string? Id;
        public readonly string? State;

        [OutputConstructor]
        private GetDedicatedAiClustersResult(
            string compartmentId,

            ImmutableArray<Outputs.GetDedicatedAiClustersDedicatedAiClusterCollectionResult> dedicatedAiClusterCollections,

            string? displayName,

            ImmutableArray<Outputs.GetDedicatedAiClustersFilterResult> filters,

            string? id,

            string? state)
        {
            CompartmentId = compartmentId;
            DedicatedAiClusterCollections = dedicatedAiClusterCollections;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            State = state;
        }
    }
}
