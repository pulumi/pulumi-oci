// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CloudMigrations.Inputs
{

    public sealed class TargetAssetMigrationAssetGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The availability domain of the instance.  Example: `Uocm:PHX-AD-1`
        /// </summary>
        [Input("availabilityDomain")]
        public Input<string>? AvailabilityDomain { get; set; }

        /// <summary>
        /// (Updatable) The OCID of the compartment.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        [Input("dependedOnBies")]
        private InputList<string>? _dependedOnBies;

        /// <summary>
        /// List of migration assets that depend on the asset.
        /// </summary>
        public InputList<string> DependedOnBies
        {
            get => _dependedOnBies ?? (_dependedOnBies = new InputList<string>());
            set => _dependedOnBies = value;
        }

        [Input("dependsOns")]
        private InputList<string>? _dependsOns;

        /// <summary>
        /// List of migration assets that depends on the asset.
        /// </summary>
        public InputList<string> DependsOns
        {
            get => _dependsOns ?? (_dependsOns = new InputList<string>());
            set => _dependsOns = value;
        }

        /// <summary>
        /// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        /// <summary>
        /// Asset ID generated by mirgration service. It is used in the mirgration service pipeline.
        /// </summary>
        [Input("id")]
        public Input<string>? Id { get; set; }

        /// <summary>
        /// A message describing the current state in more detail. For example, it can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        [Input("lifecycleDetails")]
        public Input<string>? LifecycleDetails { get; set; }

        /// <summary>
        /// OCID of the associated migration.
        /// </summary>
        [Input("migrationId")]
        public Input<string>? MigrationId { get; set; }

        [Input("notifications")]
        private InputList<string>? _notifications;

        /// <summary>
        /// List of notifications
        /// </summary>
        public InputList<string> Notifications
        {
            get => _notifications ?? (_notifications = new InputList<string>());
            set => _notifications = value;
        }

        /// <summary>
        /// The parent snapshot of the migration asset to be used by the replication task.
        /// </summary>
        [Input("parentSnapshot")]
        public Input<string>? ParentSnapshot { get; set; }

        /// <summary>
        /// Replication compartment identifier
        /// </summary>
        [Input("replicationCompartmentId")]
        public Input<string>? ReplicationCompartmentId { get; set; }

        /// <summary>
        /// Replication schedule identifier
        /// </summary>
        [Input("replicationScheduleId")]
        public Input<string>? ReplicationScheduleId { get; set; }

        /// <summary>
        /// Name of snapshot bucket
        /// </summary>
        [Input("snapShotBucketName")]
        public Input<string>? SnapShotBucketName { get; set; }

        [Input("snapshots")]
        private InputMap<object>? _snapshots;

        /// <summary>
        /// Key-value pair representing disks ID mapped to the OCIDs of replicated or hydration server volume snapshots. Example: `{"bar-key": "value"}`
        /// </summary>
        public InputMap<object> Snapshots
        {
            get => _snapshots ?? (_snapshots = new InputMap<object>());
            set => _snapshots = value;
        }

        [Input("sourceAssetData")]
        private InputMap<object>? _sourceAssetData;

        /// <summary>
        /// Key-value pair representing asset metadata keys and values scoped to a namespace. Example: `{"bar-key": "value"}`
        /// </summary>
        public InputMap<object> SourceAssetData
        {
            get => _sourceAssetData ?? (_sourceAssetData = new InputMap<object>());
            set => _sourceAssetData = value;
        }

        /// <summary>
        /// OCID that is referenced to an asset for an inventory.
        /// </summary>
        [Input("sourceAssetId")]
        public Input<string>? SourceAssetId { get; set; }

        /// <summary>
        /// The current state of the target asset.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        /// <summary>
        /// Tenancy identifier
        /// </summary>
        [Input("tenancyId")]
        public Input<string>? TenancyId { get; set; }

        /// <summary>
        /// The time when the target asset was created. An RFC3339 formatted datetime string.
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// The time when the target asset was updated. An RFC3339 formatted datetime string.
        /// </summary>
        [Input("timeUpdated")]
        public Input<string>? TimeUpdated { get; set; }

        /// <summary>
        /// (Updatable) The type of action to run when the instance is interrupted for eviction.
        /// </summary>
        [Input("type")]
        public Input<string>? Type { get; set; }

        public TargetAssetMigrationAssetGetArgs()
        {
        }
        public static new TargetAssetMigrationAssetGetArgs Empty => new TargetAssetMigrationAssetGetArgs();
    }
}