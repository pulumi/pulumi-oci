// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This resource provides the Exascale Db Storage Vault resource in Oracle Cloud Infrastructure Database service.
 *
 * Creates an Exadata Database Storage Vault
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testExascaleDbStorageVault = new oci.database.ExascaleDbStorageVault("test_exascale_db_storage_vault", {
 *     availabilityDomain: exascaleDbStorageVaultAvailabilityDomain,
 *     compartmentId: compartmentId,
 *     displayName: exascaleDbStorageVaultDisplayName,
 *     highCapacityDatabaseStorage: {
 *         totalSizeInGbs: exascaleDbStorageVaultHighCapacityDatabaseStorageTotalSizeInGbs,
 *     },
 *     additionalFlashCacheInPercent: exascaleDbStorageVaultAdditionalFlashCacheInPercent,
 *     clusterPlacementGroupId: testClusterPlacementGroup.id,
 *     definedTags: exascaleDbStorageVaultDefinedTags,
 *     description: exascaleDbStorageVaultDescription,
 *     exadataInfrastructureId: testExadataInfrastructure.id,
 *     freeformTags: {
 *         Department: "Finance",
 *     },
 *     subscriptionId: tenantSubscriptionId,
 *     timeZone: exascaleDbStorageVaultTimeZone,
 * });
 * ```
 *
 * ## Import
 *
 * ExascaleDbStorageVaults can be imported using the `id`, e.g.
 *
 * ```sh
 * $ pulumi import oci:Database/exascaleDbStorageVault:ExascaleDbStorageVault test_exascale_db_storage_vault "id"
 * ```
 */
export class ExascaleDbStorageVault extends pulumi.CustomResource {
    /**
     * Get an existing ExascaleDbStorageVault resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: ExascaleDbStorageVaultState, opts?: pulumi.CustomResourceOptions): ExascaleDbStorageVault {
        return new ExascaleDbStorageVault(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:Database/exascaleDbStorageVault:ExascaleDbStorageVault';

    /**
     * Returns true if the given object is an instance of ExascaleDbStorageVault.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is ExascaleDbStorageVault {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === ExascaleDbStorageVault.__pulumiType;
    }

    /**
     * (Updatable) The size of additional Flash Cache in percentage of High Capacity database storage.
     */
    public readonly additionalFlashCacheInPercent!: pulumi.Output<number>;
    /**
     * The name of the availability domain in which the Exadata Database Storage Vault is located.
     */
    public readonly availabilityDomain!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cluster placement group of the Exadata Infrastructure.
     */
    public readonly clusterPlacementGroupId!: pulumi.Output<string>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * (Updatable) Exadata Database Storage Vault description.
     */
    public readonly description!: pulumi.Output<string>;
    /**
     * (Updatable) The user-friendly name for the Exadata Database Storage Vault. The name does not need to be unique.
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata infrastructure.
     */
    public readonly exadataInfrastructureId!: pulumi.Output<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * (Updatable) Create exadata Database Storage Details
     */
    public readonly highCapacityDatabaseStorage!: pulumi.Output<outputs.Database.ExascaleDbStorageVaultHighCapacityDatabaseStorage>;
    /**
     * Additional information about the current lifecycle state.
     */
    public /*out*/ readonly lifecycleDetails!: pulumi.Output<string>;
    /**
     * The current state of the Exadata Database Storage Vault.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subscription with which resource needs to be associated with.
     */
    public readonly subscriptionId!: pulumi.Output<string>;
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     */
    public /*out*/ readonly systemTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * The date and time that the Exadata Database Storage Vault was created.
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The time zone that you want to use for the Exadata Database Storage Vault. For details, see [Time Zones](https://docs.cloud.oracle.com/iaas/Content/Database/References/timezones.htm). 
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    public readonly timeZone!: pulumi.Output<string>;
    /**
     * The number of Exadata VM clusters used the Exadata Database Storage Vault.
     */
    public /*out*/ readonly vmClusterCount!: pulumi.Output<number>;
    /**
     * The List of Exadata VM cluster on Exascale Infrastructure [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) **Note:** If Exadata Database Storage Vault is not used for any Exadata VM cluster on Exascale Infrastructure, this list is empty.
     */
    public /*out*/ readonly vmClusterIds!: pulumi.Output<string[]>;

    /**
     * Create a ExascaleDbStorageVault resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: ExascaleDbStorageVaultArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: ExascaleDbStorageVaultArgs | ExascaleDbStorageVaultState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as ExascaleDbStorageVaultState | undefined;
            resourceInputs["additionalFlashCacheInPercent"] = state ? state.additionalFlashCacheInPercent : undefined;
            resourceInputs["availabilityDomain"] = state ? state.availabilityDomain : undefined;
            resourceInputs["clusterPlacementGroupId"] = state ? state.clusterPlacementGroupId : undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["description"] = state ? state.description : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["exadataInfrastructureId"] = state ? state.exadataInfrastructureId : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["highCapacityDatabaseStorage"] = state ? state.highCapacityDatabaseStorage : undefined;
            resourceInputs["lifecycleDetails"] = state ? state.lifecycleDetails : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["subscriptionId"] = state ? state.subscriptionId : undefined;
            resourceInputs["systemTags"] = state ? state.systemTags : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeZone"] = state ? state.timeZone : undefined;
            resourceInputs["vmClusterCount"] = state ? state.vmClusterCount : undefined;
            resourceInputs["vmClusterIds"] = state ? state.vmClusterIds : undefined;
        } else {
            const args = argsOrState as ExascaleDbStorageVaultArgs | undefined;
            if ((!args || args.availabilityDomain === undefined) && !opts.urn) {
                throw new Error("Missing required property 'availabilityDomain'");
            }
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.displayName === undefined) && !opts.urn) {
                throw new Error("Missing required property 'displayName'");
            }
            if ((!args || args.highCapacityDatabaseStorage === undefined) && !opts.urn) {
                throw new Error("Missing required property 'highCapacityDatabaseStorage'");
            }
            resourceInputs["additionalFlashCacheInPercent"] = args ? args.additionalFlashCacheInPercent : undefined;
            resourceInputs["availabilityDomain"] = args ? args.availabilityDomain : undefined;
            resourceInputs["clusterPlacementGroupId"] = args ? args.clusterPlacementGroupId : undefined;
            resourceInputs["compartmentId"] = args ? args.compartmentId : undefined;
            resourceInputs["definedTags"] = args ? args.definedTags : undefined;
            resourceInputs["description"] = args ? args.description : undefined;
            resourceInputs["displayName"] = args ? args.displayName : undefined;
            resourceInputs["exadataInfrastructureId"] = args ? args.exadataInfrastructureId : undefined;
            resourceInputs["freeformTags"] = args ? args.freeformTags : undefined;
            resourceInputs["highCapacityDatabaseStorage"] = args ? args.highCapacityDatabaseStorage : undefined;
            resourceInputs["subscriptionId"] = args ? args.subscriptionId : undefined;
            resourceInputs["timeZone"] = args ? args.timeZone : undefined;
            resourceInputs["lifecycleDetails"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["systemTags"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["vmClusterCount"] = undefined /*out*/;
            resourceInputs["vmClusterIds"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(ExascaleDbStorageVault.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering ExascaleDbStorageVault resources.
 */
export interface ExascaleDbStorageVaultState {
    /**
     * (Updatable) The size of additional Flash Cache in percentage of High Capacity database storage.
     */
    additionalFlashCacheInPercent?: pulumi.Input<number>;
    /**
     * The name of the availability domain in which the Exadata Database Storage Vault is located.
     */
    availabilityDomain?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cluster placement group of the Exadata Infrastructure.
     */
    clusterPlacementGroupId?: pulumi.Input<string>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) Exadata Database Storage Vault description.
     */
    description?: pulumi.Input<string>;
    /**
     * (Updatable) The user-friendly name for the Exadata Database Storage Vault. The name does not need to be unique.
     */
    displayName?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata infrastructure.
     */
    exadataInfrastructureId?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) Create exadata Database Storage Details
     */
    highCapacityDatabaseStorage?: pulumi.Input<inputs.Database.ExascaleDbStorageVaultHighCapacityDatabaseStorage>;
    /**
     * Additional information about the current lifecycle state.
     */
    lifecycleDetails?: pulumi.Input<string>;
    /**
     * The current state of the Exadata Database Storage Vault.
     */
    state?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subscription with which resource needs to be associated with.
     */
    subscriptionId?: pulumi.Input<string>;
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     */
    systemTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * The date and time that the Exadata Database Storage Vault was created.
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The time zone that you want to use for the Exadata Database Storage Vault. For details, see [Time Zones](https://docs.cloud.oracle.com/iaas/Content/Database/References/timezones.htm). 
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    timeZone?: pulumi.Input<string>;
    /**
     * The number of Exadata VM clusters used the Exadata Database Storage Vault.
     */
    vmClusterCount?: pulumi.Input<number>;
    /**
     * The List of Exadata VM cluster on Exascale Infrastructure [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) **Note:** If Exadata Database Storage Vault is not used for any Exadata VM cluster on Exascale Infrastructure, this list is empty.
     */
    vmClusterIds?: pulumi.Input<pulumi.Input<string>[]>;
}

/**
 * The set of arguments for constructing a ExascaleDbStorageVault resource.
 */
export interface ExascaleDbStorageVaultArgs {
    /**
     * (Updatable) The size of additional Flash Cache in percentage of High Capacity database storage.
     */
    additionalFlashCacheInPercent?: pulumi.Input<number>;
    /**
     * The name of the availability domain in which the Exadata Database Storage Vault is located.
     */
    availabilityDomain: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cluster placement group of the Exadata Infrastructure.
     */
    clusterPlacementGroupId?: pulumi.Input<string>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) Exadata Database Storage Vault description.
     */
    description?: pulumi.Input<string>;
    /**
     * (Updatable) The user-friendly name for the Exadata Database Storage Vault. The name does not need to be unique.
     */
    displayName: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata infrastructure.
     */
    exadataInfrastructureId?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) Create exadata Database Storage Details
     */
    highCapacityDatabaseStorage: pulumi.Input<inputs.Database.ExascaleDbStorageVaultHighCapacityDatabaseStorage>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subscription with which resource needs to be associated with.
     */
    subscriptionId?: pulumi.Input<string>;
    /**
     * The time zone that you want to use for the Exadata Database Storage Vault. For details, see [Time Zones](https://docs.cloud.oracle.com/iaas/Content/Database/References/timezones.htm). 
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    timeZone?: pulumi.Input<string>;
}
