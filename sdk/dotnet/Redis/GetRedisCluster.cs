// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Redis
{
    public static class GetRedisCluster
    {
        /// <summary>
        /// This data source provides details about a specific Redis Cluster resource in Oracle Cloud Infrastructure Redis service.
        /// 
        /// Retrieves the specified Redis cluster. A Redis cluster is a memory-based storage solution. For more information, see [OCI Caching Service with Redis](https://docs.cloud.oracle.com/iaas/Content/redis/home.htm).
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
        ///     var testRedisCluster = Oci.Redis.GetRedisCluster.Invoke(new()
        ///     {
        ///         RedisClusterId = oci_redis_redis_cluster.Test_redis_cluster.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetRedisClusterResult> InvokeAsync(GetRedisClusterArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetRedisClusterResult>("oci:Redis/getRedisCluster:getRedisCluster", args ?? new GetRedisClusterArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Redis Cluster resource in Oracle Cloud Infrastructure Redis service.
        /// 
        /// Retrieves the specified Redis cluster. A Redis cluster is a memory-based storage solution. For more information, see [OCI Caching Service with Redis](https://docs.cloud.oracle.com/iaas/Content/redis/home.htm).
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
        ///     var testRedisCluster = Oci.Redis.GetRedisCluster.Invoke(new()
        ///     {
        ///         RedisClusterId = oci_redis_redis_cluster.Test_redis_cluster.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetRedisClusterResult> Invoke(GetRedisClusterInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetRedisClusterResult>("oci:Redis/getRedisCluster:getRedisCluster", args ?? new GetRedisClusterInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetRedisClusterArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm#Oracle) of the Redis cluster.
        /// </summary>
        [Input("redisClusterId", required: true)]
        public string RedisClusterId { get; set; } = null!;

        public GetRedisClusterArgs()
        {
        }
        public static new GetRedisClusterArgs Empty => new GetRedisClusterArgs();
    }

    public sealed class GetRedisClusterInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm#Oracle) of the Redis cluster.
        /// </summary>
        [Input("redisClusterId", required: true)]
        public Input<string> RedisClusterId { get; set; } = null!;

        public GetRedisClusterInvokeArgs()
        {
        }
        public static new GetRedisClusterInvokeArgs Empty => new GetRedisClusterInvokeArgs();
    }


    [OutputType]
    public sealed class GetRedisClusterResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm#Oracle) of the compartment that contains the Redis cluster.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        /// <summary>
        /// A user-friendly name of a Redis cluster node.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm#Oracle) of the Redis cluster.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// A message describing the current state in more detail. For example, the message might provide actionable information for a resource in `FAILED` state.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// The collection of Redis cluster nodes.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetRedisClusterNodeCollectionResult> NodeCollections;
        /// <summary>
        /// The number of nodes in the Redis cluster.
        /// </summary>
        public readonly int NodeCount;
        /// <summary>
        /// The amount of memory allocated to the Redis cluster's nodes, in gigabytes.
        /// </summary>
        public readonly double NodeMemoryInGbs;
        /// <summary>
        /// The private IP address of the API endpoint for the Redis cluster's primary node.
        /// </summary>
        public readonly string PrimaryEndpointIpAddress;
        /// <summary>
        /// The fully qualified domain name (FQDN) of the API endpoint for the Redis cluster's primary node.
        /// </summary>
        public readonly string PrimaryFqdn;
        public readonly string RedisClusterId;
        /// <summary>
        /// The private IP address of the API endpoint for the Redis cluster's replica nodes.
        /// </summary>
        public readonly string ReplicasEndpointIpAddress;
        /// <summary>
        /// The fully qualified domain name (FQDN) of the API endpoint for the Redis cluster's replica nodes.
        /// </summary>
        public readonly string ReplicasFqdn;
        /// <summary>
        /// The Redis version that the cluster is running.
        /// </summary>
        public readonly string SoftwareVersion;
        /// <summary>
        /// The current state of the Redis cluster.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm#Oracle) of the Redis cluster's subnet.
        /// </summary>
        public readonly string SubnetId;
        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> SystemTags;
        /// <summary>
        /// The date and time the Redis cluster was created. An [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339) formatted datetime string.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The date and time the Redis cluster was updated. An [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339) formatted datetime string.
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetRedisClusterResult(
            string compartmentId,

            ImmutableDictionary<string, object> definedTags,

            string displayName,

            ImmutableDictionary<string, object> freeformTags,

            string id,

            string lifecycleDetails,

            ImmutableArray<Outputs.GetRedisClusterNodeCollectionResult> nodeCollections,

            int nodeCount,

            double nodeMemoryInGbs,

            string primaryEndpointIpAddress,

            string primaryFqdn,

            string redisClusterId,

            string replicasEndpointIpAddress,

            string replicasFqdn,

            string softwareVersion,

            string state,

            string subnetId,

            ImmutableDictionary<string, object> systemTags,

            string timeCreated,

            string timeUpdated)
        {
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            LifecycleDetails = lifecycleDetails;
            NodeCollections = nodeCollections;
            NodeCount = nodeCount;
            NodeMemoryInGbs = nodeMemoryInGbs;
            PrimaryEndpointIpAddress = primaryEndpointIpAddress;
            PrimaryFqdn = primaryFqdn;
            RedisClusterId = redisClusterId;
            ReplicasEndpointIpAddress = replicasEndpointIpAddress;
            ReplicasFqdn = replicasFqdn;
            SoftwareVersion = softwareVersion;
            State = state;
            SubnetId = subnetId;
            SystemTags = systemTags;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
        }
    }
}