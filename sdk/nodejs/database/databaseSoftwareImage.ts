// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This resource provides the Database Software Image resource in Oracle Cloud Infrastructure Database service.
 *
 * create database software image in the specified compartment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDatabaseSoftwareImage = new oci.database.DatabaseSoftwareImage("testDatabaseSoftwareImage", {
 *     compartmentId: _var.compartment_id,
 *     displayName: _var.database_software_image_display_name,
 *     databaseSoftwareImageOneOffPatches: _var.database_software_image_database_software_image_one_off_patches,
 *     databaseVersion: _var.database_software_image_database_version,
 *     definedTags: _var.database_software_image_defined_tags,
 *     freeformTags: {
 *         Department: "Finance",
 *     },
 *     imageShapeFamily: _var.database_software_image_image_shape_family,
 *     imageType: _var.database_software_image_image_type,
 *     lsInventory: _var.database_software_image_ls_inventory,
 *     patchSet: _var.database_software_image_patch_set,
 *     sourceDbHomeId: oci_database_db_home.test_db_home.id,
 * });
 * ```
 *
 * ## Import
 *
 * DatabaseSoftwareImages can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:Database/databaseSoftwareImage:DatabaseSoftwareImage test_database_software_image "id"
 * ```
 */
export class DatabaseSoftwareImage extends pulumi.CustomResource {
    /**
     * Get an existing DatabaseSoftwareImage resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: DatabaseSoftwareImageState, opts?: pulumi.CustomResourceOptions): DatabaseSoftwareImage {
        return new DatabaseSoftwareImage(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:Database/databaseSoftwareImage:DatabaseSoftwareImage';

    /**
     * Returns true if the given object is an instance of DatabaseSoftwareImage.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is DatabaseSoftwareImage {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === DatabaseSoftwareImage.__pulumiType;
    }

    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment the database software image  belongs in.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * List of one-off patches for Database Homes.
     */
    public /*out*/ readonly databaseSoftwareImageIncludedPatches!: pulumi.Output<string[]>;
    /**
     * List of one-off patches for Database Homes.
     */
    public readonly databaseSoftwareImageOneOffPatches!: pulumi.Output<string[]>;
    /**
     * The database version with which the database software image is to be built.
     */
    public readonly databaseVersion!: pulumi.Output<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * (Updatable) The user-friendly name for the database software image. The name does not have to be unique.
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * To what shape the image is meant for.
     */
    public readonly imageShapeFamily!: pulumi.Output<string>;
    /**
     * The type of software image. Can be grid or database.
     */
    public readonly imageType!: pulumi.Output<string>;
    /**
     * The patches included in the image and the version of the image
     */
    public /*out*/ readonly includedPatchesSummary!: pulumi.Output<string>;
    /**
     * True if this Database software image is supported for Upgrade.
     */
    public /*out*/ readonly isUpgradeSupported!: pulumi.Output<boolean>;
    /**
     * Detailed message for the lifecycle state.
     */
    public /*out*/ readonly lifecycleDetails!: pulumi.Output<string>;
    /**
     * The output from the OPatch lsInventory command, which is passed as a string.
     */
    public readonly lsInventory!: pulumi.Output<string>;
    /**
     * The PSU or PBP or Release Updates. To get a list of supported versions, use the [ListDbVersions](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/DbVersionSummary/ListDbVersions) operation.
     */
    public readonly patchSet!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Database Home.
     */
    public readonly sourceDbHomeId!: pulumi.Output<string>;
    /**
     * The current state of the database software image.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * The date and time the database software image was created.
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;

    /**
     * Create a DatabaseSoftwareImage resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: DatabaseSoftwareImageArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: DatabaseSoftwareImageArgs | DatabaseSoftwareImageState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as DatabaseSoftwareImageState | undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["databaseSoftwareImageIncludedPatches"] = state ? state.databaseSoftwareImageIncludedPatches : undefined;
            resourceInputs["databaseSoftwareImageOneOffPatches"] = state ? state.databaseSoftwareImageOneOffPatches : undefined;
            resourceInputs["databaseVersion"] = state ? state.databaseVersion : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["imageShapeFamily"] = state ? state.imageShapeFamily : undefined;
            resourceInputs["imageType"] = state ? state.imageType : undefined;
            resourceInputs["includedPatchesSummary"] = state ? state.includedPatchesSummary : undefined;
            resourceInputs["isUpgradeSupported"] = state ? state.isUpgradeSupported : undefined;
            resourceInputs["lifecycleDetails"] = state ? state.lifecycleDetails : undefined;
            resourceInputs["lsInventory"] = state ? state.lsInventory : undefined;
            resourceInputs["patchSet"] = state ? state.patchSet : undefined;
            resourceInputs["sourceDbHomeId"] = state ? state.sourceDbHomeId : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
        } else {
            const args = argsOrState as DatabaseSoftwareImageArgs | undefined;
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.displayName === undefined) && !opts.urn) {
                throw new Error("Missing required property 'displayName'");
            }
            resourceInputs["compartmentId"] = args ? args.compartmentId : undefined;
            resourceInputs["databaseSoftwareImageOneOffPatches"] = args ? args.databaseSoftwareImageOneOffPatches : undefined;
            resourceInputs["databaseVersion"] = args ? args.databaseVersion : undefined;
            resourceInputs["definedTags"] = args ? args.definedTags : undefined;
            resourceInputs["displayName"] = args ? args.displayName : undefined;
            resourceInputs["freeformTags"] = args ? args.freeformTags : undefined;
            resourceInputs["imageShapeFamily"] = args ? args.imageShapeFamily : undefined;
            resourceInputs["imageType"] = args ? args.imageType : undefined;
            resourceInputs["lsInventory"] = args ? args.lsInventory : undefined;
            resourceInputs["patchSet"] = args ? args.patchSet : undefined;
            resourceInputs["sourceDbHomeId"] = args ? args.sourceDbHomeId : undefined;
            resourceInputs["databaseSoftwareImageIncludedPatches"] = undefined /*out*/;
            resourceInputs["includedPatchesSummary"] = undefined /*out*/;
            resourceInputs["isUpgradeSupported"] = undefined /*out*/;
            resourceInputs["lifecycleDetails"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(DatabaseSoftwareImage.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering DatabaseSoftwareImage resources.
 */
export interface DatabaseSoftwareImageState {
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment the database software image  belongs in.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * List of one-off patches for Database Homes.
     */
    databaseSoftwareImageIncludedPatches?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * List of one-off patches for Database Homes.
     */
    databaseSoftwareImageOneOffPatches?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * The database version with which the database software image is to be built.
     */
    databaseVersion?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) The user-friendly name for the database software image. The name does not have to be unique.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * To what shape the image is meant for.
     */
    imageShapeFamily?: pulumi.Input<string>;
    /**
     * The type of software image. Can be grid or database.
     */
    imageType?: pulumi.Input<string>;
    /**
     * The patches included in the image and the version of the image
     */
    includedPatchesSummary?: pulumi.Input<string>;
    /**
     * True if this Database software image is supported for Upgrade.
     */
    isUpgradeSupported?: pulumi.Input<boolean>;
    /**
     * Detailed message for the lifecycle state.
     */
    lifecycleDetails?: pulumi.Input<string>;
    /**
     * The output from the OPatch lsInventory command, which is passed as a string.
     */
    lsInventory?: pulumi.Input<string>;
    /**
     * The PSU or PBP or Release Updates. To get a list of supported versions, use the [ListDbVersions](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/DbVersionSummary/ListDbVersions) operation.
     */
    patchSet?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Database Home.
     */
    sourceDbHomeId?: pulumi.Input<string>;
    /**
     * The current state of the database software image.
     */
    state?: pulumi.Input<string>;
    /**
     * The date and time the database software image was created.
     */
    timeCreated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a DatabaseSoftwareImage resource.
 */
export interface DatabaseSoftwareImageArgs {
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment the database software image  belongs in.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * List of one-off patches for Database Homes.
     */
    databaseSoftwareImageOneOffPatches?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * The database version with which the database software image is to be built.
     */
    databaseVersion?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) The user-friendly name for the database software image. The name does not have to be unique.
     */
    displayName: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * To what shape the image is meant for.
     */
    imageShapeFamily?: pulumi.Input<string>;
    /**
     * The type of software image. Can be grid or database.
     */
    imageType?: pulumi.Input<string>;
    /**
     * The output from the OPatch lsInventory command, which is passed as a string.
     */
    lsInventory?: pulumi.Input<string>;
    /**
     * The PSU or PBP or Release Updates. To get a list of supported versions, use the [ListDbVersions](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/DbVersionSummary/ListDbVersions) operation.
     */
    patchSet?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Database Home.
     */
    sourceDbHomeId?: pulumi.Input<string>;
}