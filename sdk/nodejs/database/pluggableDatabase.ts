// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This resource provides the Pluggable Database resource in Oracle Cloud Infrastructure Database service.
 *
 * Creates and starts a pluggable database in the specified container database.
 * Use the [StartPluggableDatabase](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/PluggableDatabase/StartPluggableDatabase) and [StopPluggableDatabase](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/PluggableDatabase/StopPluggableDatabase) APIs to start and stop the pluggable database.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testPluggableDatabase = new oci.database.PluggableDatabase("testPluggableDatabase", {
 *     containerDatabaseId: oci_database_database.test_database.id,
 *     pdbName: _var.pluggable_database_pdb_name,
 *     definedTags: _var.pluggable_database_defined_tags,
 *     freeformTags: {
 *         Department: "Finance",
 *     },
 *     pdbAdminPassword: _var.pluggable_database_pdb_admin_password,
 *     shouldPdbAdminAccountBeLocked: _var.pluggable_database_should_pdb_admin_account_be_locked,
 *     tdeWalletPassword: _var.pluggable_database_tde_wallet_password,
 * });
 * ```
 *
 * ## Import
 *
 * PluggableDatabases can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:Database/pluggableDatabase:PluggableDatabase test_pluggable_database "id"
 * ```
 */
export class PluggableDatabase extends pulumi.CustomResource {
    /**
     * Get an existing PluggableDatabase resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: PluggableDatabaseState, opts?: pulumi.CustomResourceOptions): PluggableDatabase {
        return new PluggableDatabase(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:Database/pluggableDatabase:PluggableDatabase';

    /**
     * Returns true if the given object is an instance of PluggableDatabase.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is PluggableDatabase {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === PluggableDatabase.__pulumiType;
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    public /*out*/ readonly compartmentId!: pulumi.Output<string>;
    /**
     * Connection strings to connect to an Oracle Pluggable Database.
     */
    public /*out*/ readonly connectionStrings!: pulumi.Output<outputs.Database.PluggableDatabaseConnectionString[]>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the CDB
     */
    public readonly containerDatabaseId!: pulumi.Output<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * The restricted mode of the pluggable database. If a pluggable database is opened in restricted mode, the user needs both create a session and have restricted session privileges to connect to it.
     */
    public /*out*/ readonly isRestricted!: pulumi.Output<boolean>;
    /**
     * Detailed message for the lifecycle state.
     */
    public /*out*/ readonly lifecycleDetails!: pulumi.Output<string>;
    /**
     * The mode that pluggable database is in. Open mode can only be changed to READ_ONLY or MIGRATE directly from the backend (within the Oracle Database software).
     */
    public /*out*/ readonly openMode!: pulumi.Output<string>;
    /**
     * A strong password for PDB Admin. The password must be at least nine characters and contain at least two uppercase, two lowercase, two numbers, and two special characters. The special characters must be _, \#, or -.
     */
    public readonly pdbAdminPassword!: pulumi.Output<string>;
    /**
     * The name for the pluggable database (PDB). The name is unique in the context of a [container database](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/Database/). The name must begin with an alphabetic character and can contain a maximum of thirty alphanumeric characters. Special characters are not permitted. The pluggable database name should not be same as the container database name.
     */
    public readonly pdbName!: pulumi.Output<string>;
    /**
     * The locked mode of the pluggable database admin account. If false, the user needs to provide the PDB Admin Password to connect to it. If true, the pluggable database will be locked and user cannot login to it.
     */
    public readonly shouldPdbAdminAccountBeLocked!: pulumi.Output<boolean>;
    /**
     * The current state of the pluggable database.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * The existing TDE wallet password of the CDB.
     */
    public readonly tdeWalletPassword!: pulumi.Output<string>;
    /**
     * The date and time the pluggable database was created.
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;

    /**
     * Create a PluggableDatabase resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: PluggableDatabaseArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: PluggableDatabaseArgs | PluggableDatabaseState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as PluggableDatabaseState | undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["connectionStrings"] = state ? state.connectionStrings : undefined;
            resourceInputs["containerDatabaseId"] = state ? state.containerDatabaseId : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["isRestricted"] = state ? state.isRestricted : undefined;
            resourceInputs["lifecycleDetails"] = state ? state.lifecycleDetails : undefined;
            resourceInputs["openMode"] = state ? state.openMode : undefined;
            resourceInputs["pdbAdminPassword"] = state ? state.pdbAdminPassword : undefined;
            resourceInputs["pdbName"] = state ? state.pdbName : undefined;
            resourceInputs["shouldPdbAdminAccountBeLocked"] = state ? state.shouldPdbAdminAccountBeLocked : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["tdeWalletPassword"] = state ? state.tdeWalletPassword : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
        } else {
            const args = argsOrState as PluggableDatabaseArgs | undefined;
            if ((!args || args.containerDatabaseId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'containerDatabaseId'");
            }
            if ((!args || args.pdbName === undefined) && !opts.urn) {
                throw new Error("Missing required property 'pdbName'");
            }
            resourceInputs["containerDatabaseId"] = args ? args.containerDatabaseId : undefined;
            resourceInputs["definedTags"] = args ? args.definedTags : undefined;
            resourceInputs["freeformTags"] = args ? args.freeformTags : undefined;
            resourceInputs["pdbAdminPassword"] = args ? args.pdbAdminPassword : undefined;
            resourceInputs["pdbName"] = args ? args.pdbName : undefined;
            resourceInputs["shouldPdbAdminAccountBeLocked"] = args ? args.shouldPdbAdminAccountBeLocked : undefined;
            resourceInputs["tdeWalletPassword"] = args ? args.tdeWalletPassword : undefined;
            resourceInputs["compartmentId"] = undefined /*out*/;
            resourceInputs["connectionStrings"] = undefined /*out*/;
            resourceInputs["isRestricted"] = undefined /*out*/;
            resourceInputs["lifecycleDetails"] = undefined /*out*/;
            resourceInputs["openMode"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(PluggableDatabase.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering PluggableDatabase resources.
 */
export interface PluggableDatabaseState {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * Connection strings to connect to an Oracle Pluggable Database.
     */
    connectionStrings?: pulumi.Input<pulumi.Input<inputs.Database.PluggableDatabaseConnectionString>[]>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the CDB
     */
    containerDatabaseId?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * The restricted mode of the pluggable database. If a pluggable database is opened in restricted mode, the user needs both create a session and have restricted session privileges to connect to it.
     */
    isRestricted?: pulumi.Input<boolean>;
    /**
     * Detailed message for the lifecycle state.
     */
    lifecycleDetails?: pulumi.Input<string>;
    /**
     * The mode that pluggable database is in. Open mode can only be changed to READ_ONLY or MIGRATE directly from the backend (within the Oracle Database software).
     */
    openMode?: pulumi.Input<string>;
    /**
     * A strong password for PDB Admin. The password must be at least nine characters and contain at least two uppercase, two lowercase, two numbers, and two special characters. The special characters must be _, \#, or -.
     */
    pdbAdminPassword?: pulumi.Input<string>;
    /**
     * The name for the pluggable database (PDB). The name is unique in the context of a [container database](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/Database/). The name must begin with an alphabetic character and can contain a maximum of thirty alphanumeric characters. Special characters are not permitted. The pluggable database name should not be same as the container database name.
     */
    pdbName?: pulumi.Input<string>;
    /**
     * The locked mode of the pluggable database admin account. If false, the user needs to provide the PDB Admin Password to connect to it. If true, the pluggable database will be locked and user cannot login to it.
     */
    shouldPdbAdminAccountBeLocked?: pulumi.Input<boolean>;
    /**
     * The current state of the pluggable database.
     */
    state?: pulumi.Input<string>;
    /**
     * The existing TDE wallet password of the CDB.
     */
    tdeWalletPassword?: pulumi.Input<string>;
    /**
     * The date and time the pluggable database was created.
     */
    timeCreated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a PluggableDatabase resource.
 */
export interface PluggableDatabaseArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the CDB
     */
    containerDatabaseId: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * A strong password for PDB Admin. The password must be at least nine characters and contain at least two uppercase, two lowercase, two numbers, and two special characters. The special characters must be _, \#, or -.
     */
    pdbAdminPassword?: pulumi.Input<string>;
    /**
     * The name for the pluggable database (PDB). The name is unique in the context of a [container database](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/Database/). The name must begin with an alphabetic character and can contain a maximum of thirty alphanumeric characters. Special characters are not permitted. The pluggable database name should not be same as the container database name.
     */
    pdbName: pulumi.Input<string>;
    /**
     * The locked mode of the pluggable database admin account. If false, the user needs to provide the PDB Admin Password to connect to it. If true, the pluggable database will be locked and user cannot login to it.
     */
    shouldPdbAdminAccountBeLocked?: pulumi.Input<boolean>;
    /**
     * The existing TDE wallet password of the CDB.
     */
    tdeWalletPassword?: pulumi.Input<string>;
}
