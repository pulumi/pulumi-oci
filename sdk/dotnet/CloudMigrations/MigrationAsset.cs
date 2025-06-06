// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CloudMigrations
{
    /// <summary>
    /// This resource provides the Migration Asset resource in Oracle Cloud Infrastructure Cloud Migrations service.
    /// 
    /// Creates a migration asset.
    /// 
    /// ## Import
    /// 
    /// MigrationAssets can be imported using the `id`, e.g.
    /// 
    /// ```sh
    /// $ pulumi import oci:CloudMigrations/migrationAsset:MigrationAsset test_migration_asset "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:CloudMigrations/migrationAsset:MigrationAsset")]
    public partial class MigrationAsset : global::Pulumi.CustomResource
    {
        /// <summary>
        /// Availability domain
        /// </summary>
        [Output("availabilityDomain")]
        public Output<string> AvailabilityDomain { get; private set; } = null!;

        /// <summary>
        /// Compartment Identifier
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// List of migration assets that depend on the asset.
        /// </summary>
        [Output("dependedOnBies")]
        public Output<ImmutableArray<string>> DependedOnBies { get; private set; } = null!;

        /// <summary>
        /// (Updatable) A user-friendly name. If empty, then source asset name will be used. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// OCID of an asset for an inventory.
        /// </summary>
        [Output("inventoryAssetId")]
        public Output<string> InventoryAssetId { get; private set; } = null!;

        /// <summary>
        /// A message describing the current state in more detail. For example, it can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        [Output("lifecycleDetails")]
        public Output<string> LifecycleDetails { get; private set; } = null!;

        [Output("migrationAssetDependsOns")]
        public Output<ImmutableArray<string>> MigrationAssetDependsOns { get; private set; } = null!;

        /// <summary>
        /// OCID of the associated migration.
        /// </summary>
        [Output("migrationId")]
        public Output<string> MigrationId { get; private set; } = null!;

        /// <summary>
        /// List of notifications
        /// </summary>
        [Output("notifications")]
        public Output<ImmutableArray<string>> Notifications { get; private set; } = null!;

        /// <summary>
        /// The parent snapshot of the migration asset to be used by the replication task.
        /// </summary>
        [Output("parentSnapshot")]
        public Output<string> ParentSnapshot { get; private set; } = null!;

        /// <summary>
        /// Replication compartment identifier
        /// </summary>
        [Output("replicationCompartmentId")]
        public Output<string> ReplicationCompartmentId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Replication schedule identifier
        /// </summary>
        [Output("replicationScheduleId")]
        public Output<string> ReplicationScheduleId { get; private set; } = null!;

        /// <summary>
        /// Name of snapshot bucket
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Output("snapShotBucketName")]
        public Output<string> SnapShotBucketName { get; private set; } = null!;

        /// <summary>
        /// Key-value pair representing disks ID mapped to the OCIDs of replicated or hydration server volume snapshots. Example: `{"bar-key": "value"}`
        /// </summary>
        [Output("snapshots")]
        public Output<ImmutableDictionary<string, string>> Snapshots { get; private set; } = null!;

        /// <summary>
        /// OCID that is referenced to an asset for an inventory.
        /// </summary>
        [Output("sourceAssetId")]
        public Output<string> SourceAssetId { get; private set; } = null!;

        /// <summary>
        /// The current state of the migration asset.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// Tenancy identifier
        /// </summary>
        [Output("tenancyId")]
        public Output<string> TenancyId { get; private set; } = null!;

        /// <summary>
        /// The time when the migration asset was created. An RFC3339 formatted datetime string.
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// The time when the migration asset was updated. An RFC3339 formatted datetime string.
        /// </summary>
        [Output("timeUpdated")]
        public Output<string> TimeUpdated { get; private set; } = null!;

        /// <summary>
        /// The type of asset referenced for inventory.
        /// </summary>
        [Output("type")]
        public Output<string> Type { get; private set; } = null!;


        /// <summary>
        /// Create a MigrationAsset resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public MigrationAsset(string name, MigrationAssetArgs args, CustomResourceOptions? options = null)
            : base("oci:CloudMigrations/migrationAsset:MigrationAsset", name, args ?? new MigrationAssetArgs(), MakeResourceOptions(options, ""))
        {
        }

        private MigrationAsset(string name, Input<string> id, MigrationAssetState? state = null, CustomResourceOptions? options = null)
            : base("oci:CloudMigrations/migrationAsset:MigrationAsset", name, state, MakeResourceOptions(options, id))
        {
        }

        private static CustomResourceOptions MakeResourceOptions(CustomResourceOptions? options, Input<string>? id)
        {
            var defaultOptions = new CustomResourceOptions
            {
                Version = Utilities.Version,
            };
            var merged = CustomResourceOptions.Merge(defaultOptions, options);
            // Override the ID if one was specified for consistency with other language SDKs.
            merged.Id = id ?? merged.Id;
            return merged;
        }
        /// <summary>
        /// Get an existing MigrationAsset resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static MigrationAsset Get(string name, Input<string> id, MigrationAssetState? state = null, CustomResourceOptions? options = null)
        {
            return new MigrationAsset(name, id, state, options);
        }
    }

    public sealed class MigrationAssetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// Availability domain
        /// </summary>
        [Input("availabilityDomain", required: true)]
        public Input<string> AvailabilityDomain { get; set; } = null!;

        /// <summary>
        /// (Updatable) A user-friendly name. If empty, then source asset name will be used. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        /// <summary>
        /// OCID of an asset for an inventory.
        /// </summary>
        [Input("inventoryAssetId", required: true)]
        public Input<string> InventoryAssetId { get; set; } = null!;

        [Input("migrationAssetDependsOns")]
        private InputList<string>? _migrationAssetDependsOns;
        public InputList<string> MigrationAssetDependsOns
        {
            get => _migrationAssetDependsOns ?? (_migrationAssetDependsOns = new InputList<string>());
            set => _migrationAssetDependsOns = value;
        }

        /// <summary>
        /// OCID of the associated migration.
        /// </summary>
        [Input("migrationId", required: true)]
        public Input<string> MigrationId { get; set; } = null!;

        /// <summary>
        /// Replication compartment identifier
        /// </summary>
        [Input("replicationCompartmentId", required: true)]
        public Input<string> ReplicationCompartmentId { get; set; } = null!;

        /// <summary>
        /// (Updatable) Replication schedule identifier
        /// </summary>
        [Input("replicationScheduleId")]
        public Input<string>? ReplicationScheduleId { get; set; }

        /// <summary>
        /// Name of snapshot bucket
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("snapShotBucketName", required: true)]
        public Input<string> SnapShotBucketName { get; set; } = null!;

        public MigrationAssetArgs()
        {
        }
        public static new MigrationAssetArgs Empty => new MigrationAssetArgs();
    }

    public sealed class MigrationAssetState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// Availability domain
        /// </summary>
        [Input("availabilityDomain")]
        public Input<string>? AvailabilityDomain { get; set; }

        /// <summary>
        /// Compartment Identifier
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

        /// <summary>
        /// (Updatable) A user-friendly name. If empty, then source asset name will be used. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        /// <summary>
        /// OCID of an asset for an inventory.
        /// </summary>
        [Input("inventoryAssetId")]
        public Input<string>? InventoryAssetId { get; set; }

        /// <summary>
        /// A message describing the current state in more detail. For example, it can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        [Input("lifecycleDetails")]
        public Input<string>? LifecycleDetails { get; set; }

        [Input("migrationAssetDependsOns")]
        private InputList<string>? _migrationAssetDependsOns;
        public InputList<string> MigrationAssetDependsOns
        {
            get => _migrationAssetDependsOns ?? (_migrationAssetDependsOns = new InputList<string>());
            set => _migrationAssetDependsOns = value;
        }

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
        /// (Updatable) Replication schedule identifier
        /// </summary>
        [Input("replicationScheduleId")]
        public Input<string>? ReplicationScheduleId { get; set; }

        /// <summary>
        /// Name of snapshot bucket
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("snapShotBucketName")]
        public Input<string>? SnapShotBucketName { get; set; }

        [Input("snapshots")]
        private InputMap<string>? _snapshots;

        /// <summary>
        /// Key-value pair representing disks ID mapped to the OCIDs of replicated or hydration server volume snapshots. Example: `{"bar-key": "value"}`
        /// </summary>
        public InputMap<string> Snapshots
        {
            get => _snapshots ?? (_snapshots = new InputMap<string>());
            set => _snapshots = value;
        }

        /// <summary>
        /// OCID that is referenced to an asset for an inventory.
        /// </summary>
        [Input("sourceAssetId")]
        public Input<string>? SourceAssetId { get; set; }

        /// <summary>
        /// The current state of the migration asset.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        /// <summary>
        /// Tenancy identifier
        /// </summary>
        [Input("tenancyId")]
        public Input<string>? TenancyId { get; set; }

        /// <summary>
        /// The time when the migration asset was created. An RFC3339 formatted datetime string.
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// The time when the migration asset was updated. An RFC3339 formatted datetime string.
        /// </summary>
        [Input("timeUpdated")]
        public Input<string>? TimeUpdated { get; set; }

        /// <summary>
        /// The type of asset referenced for inventory.
        /// </summary>
        [Input("type")]
        public Input<string>? Type { get; set; }

        public MigrationAssetState()
        {
        }
        public static new MigrationAssetState Empty => new MigrationAssetState();
    }
}
