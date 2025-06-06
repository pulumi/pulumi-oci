// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.FileStorage
{
    public static class GetReplicationTarget
    {
        /// <summary>
        /// This data source provides details about a specific Replication Target resource in Oracle Cloud Infrastructure File Storage service.
        /// 
        /// Gets the specified replication target's information.
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
        ///     var testReplicationTarget = Oci.FileStorage.GetReplicationTarget.Invoke(new()
        ///     {
        ///         ReplicationTargetId = testReplicationTargetOciFileStorageReplicationTarget.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetReplicationTargetResult> InvokeAsync(GetReplicationTargetArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetReplicationTargetResult>("oci:FileStorage/getReplicationTarget:getReplicationTarget", args ?? new GetReplicationTargetArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Replication Target resource in Oracle Cloud Infrastructure File Storage service.
        /// 
        /// Gets the specified replication target's information.
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
        ///     var testReplicationTarget = Oci.FileStorage.GetReplicationTarget.Invoke(new()
        ///     {
        ///         ReplicationTargetId = testReplicationTargetOciFileStorageReplicationTarget.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetReplicationTargetResult> Invoke(GetReplicationTargetInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetReplicationTargetResult>("oci:FileStorage/getReplicationTarget:getReplicationTarget", args ?? new GetReplicationTargetInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Replication Target resource in Oracle Cloud Infrastructure File Storage service.
        /// 
        /// Gets the specified replication target's information.
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
        ///     var testReplicationTarget = Oci.FileStorage.GetReplicationTarget.Invoke(new()
        ///     {
        ///         ReplicationTargetId = testReplicationTargetOciFileStorageReplicationTarget.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetReplicationTargetResult> Invoke(GetReplicationTargetInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetReplicationTargetResult>("oci:FileStorage/getReplicationTarget:getReplicationTarget", args ?? new GetReplicationTargetInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetReplicationTargetArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the replication target.
        /// </summary>
        [Input("replicationTargetId", required: true)]
        public string ReplicationTargetId { get; set; } = null!;

        public GetReplicationTargetArgs()
        {
        }
        public static new GetReplicationTargetArgs Empty => new GetReplicationTargetArgs();
    }

    public sealed class GetReplicationTargetInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the replication target.
        /// </summary>
        [Input("replicationTargetId", required: true)]
        public Input<string> ReplicationTargetId { get; set; } = null!;

        public GetReplicationTargetInvokeArgs()
        {
        }
        public static new GetReplicationTargetInvokeArgs Empty => new GetReplicationTargetInvokeArgs();
    }


    [OutputType]
    public sealed class GetReplicationTargetResult
    {
        /// <summary>
        /// The availability domain the replication target is in. Must be in the same availability domain as the target file system. Example: `Uocm:PHX-AD-1`
        /// </summary>
        public readonly string AvailabilityDomain;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the replication.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// Percentage progress of the current replication cycle.
        /// </summary>
        public readonly string DeltaProgress;
        /// <summary>
        /// The current state of the snapshot during replication operations.
        /// </summary>
        public readonly string DeltaStatus;
        /// <summary>
        /// A user-friendly name. This name is same as the replication display name for the associated resource. Example: `My Replication`
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the last snapshot snapshot which was completely applied to the target file system. Empty while the initial snapshot is being applied.
        /// </summary>
        public readonly string LastSnapshotId;
        /// <summary>
        /// Additional information about the current `lifecycleState`.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// The snapshotTime of the most recent recoverable replication snapshot in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format. Example: `2021-04-04T20:01:29.100Z`
        /// </summary>
        public readonly string RecoveryPointTime;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of replication.
        /// </summary>
        public readonly string ReplicationId;
        public readonly string ReplicationTargetId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of source filesystem.
        /// </summary>
        public readonly string SourceId;
        /// <summary>
        /// The current state of this replication.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// System tags for this resource. System tags are applied to resources by internal Oracle Cloud Infrastructure services.
        /// </summary>
        public readonly ImmutableDictionary<string, string> SystemTags;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of target filesystem.
        /// </summary>
        public readonly string TargetId;
        /// <summary>
        /// The date and time the replication target was created in target region. in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format. Example: `2021-01-04T20:01:29.100Z`
        /// </summary>
        public readonly string TimeCreated;

        [OutputConstructor]
        private GetReplicationTargetResult(
            string availabilityDomain,

            string compartmentId,

            ImmutableDictionary<string, string> definedTags,

            string deltaProgress,

            string deltaStatus,

            string displayName,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            string lastSnapshotId,

            string lifecycleDetails,

            string recoveryPointTime,

            string replicationId,

            string replicationTargetId,

            string sourceId,

            string state,

            ImmutableDictionary<string, string> systemTags,

            string targetId,

            string timeCreated)
        {
            AvailabilityDomain = availabilityDomain;
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            DeltaProgress = deltaProgress;
            DeltaStatus = deltaStatus;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            LastSnapshotId = lastSnapshotId;
            LifecycleDetails = lifecycleDetails;
            RecoveryPointTime = recoveryPointTime;
            ReplicationId = replicationId;
            ReplicationTargetId = replicationTargetId;
            SourceId = sourceId;
            State = state;
            SystemTags = systemTags;
            TargetId = targetId;
            TimeCreated = timeCreated;
        }
    }
}
