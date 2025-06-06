// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database
{
    /// <summary>
    /// This resource provides the Exascale Db Storage Vault resource in Oracle Cloud Infrastructure Database service.
    /// 
    /// Creates an Exadata Database Storage Vault
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
    ///     var testExascaleDbStorageVault = new Oci.Database.ExascaleDbStorageVault("test_exascale_db_storage_vault", new()
    ///     {
    ///         AvailabilityDomain = exascaleDbStorageVaultAvailabilityDomain,
    ///         CompartmentId = compartmentId,
    ///         DisplayName = exascaleDbStorageVaultDisplayName,
    ///         HighCapacityDatabaseStorage = new Oci.Database.Inputs.ExascaleDbStorageVaultHighCapacityDatabaseStorageArgs
    ///         {
    ///             TotalSizeInGbs = exascaleDbStorageVaultHighCapacityDatabaseStorageTotalSizeInGbs,
    ///         },
    ///         AdditionalFlashCacheInPercent = exascaleDbStorageVaultAdditionalFlashCacheInPercent,
    ///         ClusterPlacementGroupId = testClusterPlacementGroup.Id,
    ///         DefinedTags = exascaleDbStorageVaultDefinedTags,
    ///         Description = exascaleDbStorageVaultDescription,
    ///         ExadataInfrastructureId = testExadataInfrastructure.Id,
    ///         FreeformTags = 
    ///         {
    ///             { "Department", "Finance" },
    ///         },
    ///         SubscriptionId = tenantSubscriptionId,
    ///         TimeZone = exascaleDbStorageVaultTimeZone,
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// ExascaleDbStorageVaults can be imported using the `id`, e.g.
    /// 
    /// ```sh
    /// $ pulumi import oci:Database/exascaleDbStorageVault:ExascaleDbStorageVault test_exascale_db_storage_vault "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:Database/exascaleDbStorageVault:ExascaleDbStorageVault")]
    public partial class ExascaleDbStorageVault : global::Pulumi.CustomResource
    {
        /// <summary>
        /// (Updatable) The size of additional Flash Cache in percentage of High Capacity database storage.
        /// </summary>
        [Output("additionalFlashCacheInPercent")]
        public Output<int> AdditionalFlashCacheInPercent { get; private set; } = null!;

        /// <summary>
        /// The name of the availability domain in which the Exadata Database Storage Vault is located.
        /// </summary>
        [Output("availabilityDomain")]
        public Output<string> AvailabilityDomain { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cluster placement group of the Exadata Infrastructure.
        /// </summary>
        [Output("clusterPlacementGroupId")]
        public Output<string> ClusterPlacementGroupId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, string>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Exadata Database Storage Vault description.
        /// </summary>
        [Output("description")]
        public Output<string> Description { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The user-friendly name for the Exadata Database Storage Vault. The name does not need to be unique.
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata infrastructure.
        /// </summary>
        [Output("exadataInfrastructureId")]
        public Output<string> ExadataInfrastructureId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, string>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Create exadata Database Storage Details
        /// </summary>
        [Output("highCapacityDatabaseStorage")]
        public Output<Outputs.ExascaleDbStorageVaultHighCapacityDatabaseStorage> HighCapacityDatabaseStorage { get; private set; } = null!;

        /// <summary>
        /// Additional information about the current lifecycle state.
        /// </summary>
        [Output("lifecycleDetails")]
        public Output<string> LifecycleDetails { get; private set; } = null!;

        /// <summary>
        /// The current state of the Exadata Database Storage Vault.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subscription with which resource needs to be associated with.
        /// </summary>
        [Output("subscriptionId")]
        public Output<string> SubscriptionId { get; private set; } = null!;

        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        /// </summary>
        [Output("systemTags")]
        public Output<ImmutableDictionary<string, string>> SystemTags { get; private set; } = null!;

        /// <summary>
        /// The date and time that the Exadata Database Storage Vault was created.
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// The time zone that you want to use for the Exadata Database Storage Vault. For details, see [Time Zones](https://docs.cloud.oracle.com/iaas/Content/Database/References/timezones.htm). 
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Output("timeZone")]
        public Output<string> TimeZone { get; private set; } = null!;

        /// <summary>
        /// The number of Exadata VM clusters used the Exadata Database Storage Vault.
        /// </summary>
        [Output("vmClusterCount")]
        public Output<int> VmClusterCount { get; private set; } = null!;

        /// <summary>
        /// The List of Exadata VM cluster on Exascale Infrastructure [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) **Note:** If Exadata Database Storage Vault is not used for any Exadata VM cluster on Exascale Infrastructure, this list is empty.
        /// </summary>
        [Output("vmClusterIds")]
        public Output<ImmutableArray<string>> VmClusterIds { get; private set; } = null!;


        /// <summary>
        /// Create a ExascaleDbStorageVault resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public ExascaleDbStorageVault(string name, ExascaleDbStorageVaultArgs args, CustomResourceOptions? options = null)
            : base("oci:Database/exascaleDbStorageVault:ExascaleDbStorageVault", name, args ?? new ExascaleDbStorageVaultArgs(), MakeResourceOptions(options, ""))
        {
        }

        private ExascaleDbStorageVault(string name, Input<string> id, ExascaleDbStorageVaultState? state = null, CustomResourceOptions? options = null)
            : base("oci:Database/exascaleDbStorageVault:ExascaleDbStorageVault", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing ExascaleDbStorageVault resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static ExascaleDbStorageVault Get(string name, Input<string> id, ExascaleDbStorageVaultState? state = null, CustomResourceOptions? options = null)
        {
            return new ExascaleDbStorageVault(name, id, state, options);
        }
    }

    public sealed class ExascaleDbStorageVaultArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The size of additional Flash Cache in percentage of High Capacity database storage.
        /// </summary>
        [Input("additionalFlashCacheInPercent")]
        public Input<int>? AdditionalFlashCacheInPercent { get; set; }

        /// <summary>
        /// The name of the availability domain in which the Exadata Database Storage Vault is located.
        /// </summary>
        [Input("availabilityDomain", required: true)]
        public Input<string> AvailabilityDomain { get; set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cluster placement group of the Exadata Infrastructure.
        /// </summary>
        [Input("clusterPlacementGroupId")]
        public Input<string>? ClusterPlacementGroupId { get; set; }

        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        [Input("definedTags")]
        private InputMap<string>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        /// </summary>
        public InputMap<string> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<string>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) Exadata Database Storage Vault description.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// (Updatable) The user-friendly name for the Exadata Database Storage Vault. The name does not need to be unique.
        /// </summary>
        [Input("displayName", required: true)]
        public Input<string> DisplayName { get; set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata infrastructure.
        /// </summary>
        [Input("exadataInfrastructureId")]
        public Input<string>? ExadataInfrastructureId { get; set; }

        [Input("freeformTags")]
        private InputMap<string>? _freeformTags;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public InputMap<string> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<string>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// (Updatable) Create exadata Database Storage Details
        /// </summary>
        [Input("highCapacityDatabaseStorage", required: true)]
        public Input<Inputs.ExascaleDbStorageVaultHighCapacityDatabaseStorageArgs> HighCapacityDatabaseStorage { get; set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subscription with which resource needs to be associated with.
        /// </summary>
        [Input("subscriptionId")]
        public Input<string>? SubscriptionId { get; set; }

        /// <summary>
        /// The time zone that you want to use for the Exadata Database Storage Vault. For details, see [Time Zones](https://docs.cloud.oracle.com/iaas/Content/Database/References/timezones.htm). 
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("timeZone")]
        public Input<string>? TimeZone { get; set; }

        public ExascaleDbStorageVaultArgs()
        {
        }
        public static new ExascaleDbStorageVaultArgs Empty => new ExascaleDbStorageVaultArgs();
    }

    public sealed class ExascaleDbStorageVaultState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The size of additional Flash Cache in percentage of High Capacity database storage.
        /// </summary>
        [Input("additionalFlashCacheInPercent")]
        public Input<int>? AdditionalFlashCacheInPercent { get; set; }

        /// <summary>
        /// The name of the availability domain in which the Exadata Database Storage Vault is located.
        /// </summary>
        [Input("availabilityDomain")]
        public Input<string>? AvailabilityDomain { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cluster placement group of the Exadata Infrastructure.
        /// </summary>
        [Input("clusterPlacementGroupId")]
        public Input<string>? ClusterPlacementGroupId { get; set; }

        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        [Input("definedTags")]
        private InputMap<string>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        /// </summary>
        public InputMap<string> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<string>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) Exadata Database Storage Vault description.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// (Updatable) The user-friendly name for the Exadata Database Storage Vault. The name does not need to be unique.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata infrastructure.
        /// </summary>
        [Input("exadataInfrastructureId")]
        public Input<string>? ExadataInfrastructureId { get; set; }

        [Input("freeformTags")]
        private InputMap<string>? _freeformTags;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public InputMap<string> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<string>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// (Updatable) Create exadata Database Storage Details
        /// </summary>
        [Input("highCapacityDatabaseStorage")]
        public Input<Inputs.ExascaleDbStorageVaultHighCapacityDatabaseStorageGetArgs>? HighCapacityDatabaseStorage { get; set; }

        /// <summary>
        /// Additional information about the current lifecycle state.
        /// </summary>
        [Input("lifecycleDetails")]
        public Input<string>? LifecycleDetails { get; set; }

        /// <summary>
        /// The current state of the Exadata Database Storage Vault.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subscription with which resource needs to be associated with.
        /// </summary>
        [Input("subscriptionId")]
        public Input<string>? SubscriptionId { get; set; }

        [Input("systemTags")]
        private InputMap<string>? _systemTags;

        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        /// </summary>
        public InputMap<string> SystemTags
        {
            get => _systemTags ?? (_systemTags = new InputMap<string>());
            set => _systemTags = value;
        }

        /// <summary>
        /// The date and time that the Exadata Database Storage Vault was created.
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// The time zone that you want to use for the Exadata Database Storage Vault. For details, see [Time Zones](https://docs.cloud.oracle.com/iaas/Content/Database/References/timezones.htm). 
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("timeZone")]
        public Input<string>? TimeZone { get; set; }

        /// <summary>
        /// The number of Exadata VM clusters used the Exadata Database Storage Vault.
        /// </summary>
        [Input("vmClusterCount")]
        public Input<int>? VmClusterCount { get; set; }

        [Input("vmClusterIds")]
        private InputList<string>? _vmClusterIds;

        /// <summary>
        /// The List of Exadata VM cluster on Exascale Infrastructure [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) **Note:** If Exadata Database Storage Vault is not used for any Exadata VM cluster on Exascale Infrastructure, this list is empty.
        /// </summary>
        public InputList<string> VmClusterIds
        {
            get => _vmClusterIds ?? (_vmClusterIds = new InputList<string>());
            set => _vmClusterIds = value;
        }

        public ExascaleDbStorageVaultState()
        {
        }
        public static new ExascaleDbStorageVaultState Empty => new ExascaleDbStorageVaultState();
    }
}
