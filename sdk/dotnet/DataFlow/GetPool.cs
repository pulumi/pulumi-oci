// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataFlow
{
    public static class GetPool
    {
        /// <summary>
        /// This data source provides details about a specific Pool resource in Oracle Cloud Infrastructure Data Flow service.
        /// 
        /// Retrieves a pool using a `poolId`.
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
        ///     var testPool = Oci.DataFlow.GetPool.Invoke(new()
        ///     {
        ///         PoolId = testPoolOciDataflowPool.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetPoolResult> InvokeAsync(GetPoolArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetPoolResult>("oci:DataFlow/getPool:getPool", args ?? new GetPoolArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Pool resource in Oracle Cloud Infrastructure Data Flow service.
        /// 
        /// Retrieves a pool using a `poolId`.
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
        ///     var testPool = Oci.DataFlow.GetPool.Invoke(new()
        ///     {
        ///         PoolId = testPoolOciDataflowPool.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetPoolResult> Invoke(GetPoolInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetPoolResult>("oci:DataFlow/getPool:getPool", args ?? new GetPoolInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Pool resource in Oracle Cloud Infrastructure Data Flow service.
        /// 
        /// Retrieves a pool using a `poolId`.
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
        ///     var testPool = Oci.DataFlow.GetPool.Invoke(new()
        ///     {
        ///         PoolId = testPoolOciDataflowPool.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetPoolResult> Invoke(GetPoolInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetPoolResult>("oci:DataFlow/getPool:getPool", args ?? new GetPoolInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetPoolArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The unique ID for a pool.
        /// </summary>
        [Input("poolId", required: true)]
        public string PoolId { get; set; } = null!;

        public GetPoolArgs()
        {
        }
        public static new GetPoolArgs Empty => new GetPoolArgs();
    }

    public sealed class GetPoolInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The unique ID for a pool.
        /// </summary>
        [Input("poolId", required: true)]
        public Input<string> PoolId { get; set; } = null!;

        public GetPoolInvokeArgs()
        {
        }
        public static new GetPoolInvokeArgs Empty => new GetPoolInvokeArgs();
    }


    [OutputType]
    public sealed class GetPoolResult
    {
        /// <summary>
        /// The OCID of a compartment.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// List of PoolConfig items.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetPoolConfigurationResult> Configurations;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// A user-friendly description. Avoid entering confidential information.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// A user-friendly name. It does not have to be unique. Avoid entering confidential information.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// The OCID of a pool. Unique Id to indentify a dataflow pool resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Optional timeout value in minutes used to auto stop Pools. A Pool will be auto stopped after inactivity for this amount of time period. If value not set, pool will not be auto stopped auto.
        /// </summary>
        public readonly int IdleTimeoutInMinutes;
        /// <summary>
        /// The detailed messages about the lifecycle state.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// The OCID of the user who created the resource.
        /// </summary>
        public readonly string OwnerPrincipalId;
        /// <summary>
        /// The username of the user who created the resource.  If the username of the owner does not exist, `null` will be returned and the caller should refer to the ownerPrincipalId value instead.
        /// </summary>
        public readonly string OwnerUserName;
        public readonly string PoolId;
        /// <summary>
        /// A collection of metrics related to a particular pool.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetPoolPoolMetricResult> PoolMetrics;
        /// <summary>
        /// A list of schedules for pool to auto start and stop.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetPoolScheduleResult> Schedules;
        /// <summary>
        /// The current state of this pool.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The date and time the resource was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2018-04-03T21:10:29.600Z`
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The date and time the resource was updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2018-04-03T21:10:29.600Z`
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetPoolResult(
            string compartmentId,

            ImmutableArray<Outputs.GetPoolConfigurationResult> configurations,

            ImmutableDictionary<string, string> definedTags,

            string description,

            string displayName,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            int idleTimeoutInMinutes,

            string lifecycleDetails,

            string ownerPrincipalId,

            string ownerUserName,

            string poolId,

            ImmutableArray<Outputs.GetPoolPoolMetricResult> poolMetrics,

            ImmutableArray<Outputs.GetPoolScheduleResult> schedules,

            string state,

            string timeCreated,

            string timeUpdated)
        {
            CompartmentId = compartmentId;
            Configurations = configurations;
            DefinedTags = definedTags;
            Description = description;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            IdleTimeoutInMinutes = idleTimeoutInMinutes;
            LifecycleDetails = lifecycleDetails;
            OwnerPrincipalId = ownerPrincipalId;
            OwnerUserName = ownerUserName;
            PoolId = poolId;
            PoolMetrics = poolMetrics;
            Schedules = schedules;
            State = state;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
        }
    }
}
