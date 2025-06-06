// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This resource provides the Migration resource in Oracle Cloud Infrastructure Cloud Migrations service.
 *
 * Creates a migration.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testMigration = new oci.cloudmigrations.Migration("test_migration", {
 *     compartmentId: compartmentId,
 *     displayName: migrationDisplayName,
 *     definedTags: {
 *         "foo-namespace.bar-key": "value",
 *     },
 *     freeformTags: {
 *         "bar-key": "value",
 *     },
 *     isCompleted: migrationIsCompleted,
 *     replicationScheduleId: testReplicationSchedule.id,
 * });
 * ```
 *
 * ## Import
 *
 * Migrations can be imported using the `id`, e.g.
 *
 * ```sh
 * $ pulumi import oci:CloudMigrations/migration:Migration test_migration "id"
 * ```
 */
export class Migration extends pulumi.CustomResource {
    /**
     * Get an existing Migration resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: MigrationState, opts?: pulumi.CustomResourceOptions): Migration {
        return new Migration(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:CloudMigrations/migration:Migration';

    /**
     * Returns true if the given object is an instance of Migration.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is Migration {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === Migration.__pulumiType;
    }

    /**
     * (Updatable) Compartment identifier
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * (Updatable) Migration identifier
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. It exists only for cross-compatibility. Example: `{"bar-key": "value"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * (Updatable) Indicates whether migration is marked as complete.
     */
    public readonly isCompleted!: pulumi.Output<boolean>;
    /**
     * A message describing the current state in more detail. For example, it can be used to provide actionable information for a resource in Failed state.
     */
    public /*out*/ readonly lifecycleDetails!: pulumi.Output<string>;
    /**
     * (Updatable) Replication schedule identifier
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    public readonly replicationScheduleId!: pulumi.Output<string>;
    /**
     * The current state of migration.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    public /*out*/ readonly systemTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * The time when the migration project was created. An RFC3339 formatted datetime string
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The time when the migration project was updated. An RFC3339 formatted datetime string
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;

    /**
     * Create a Migration resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: MigrationArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: MigrationArgs | MigrationState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as MigrationState | undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["isCompleted"] = state ? state.isCompleted : undefined;
            resourceInputs["lifecycleDetails"] = state ? state.lifecycleDetails : undefined;
            resourceInputs["replicationScheduleId"] = state ? state.replicationScheduleId : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["systemTags"] = state ? state.systemTags : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeUpdated"] = state ? state.timeUpdated : undefined;
        } else {
            const args = argsOrState as MigrationArgs | undefined;
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.displayName === undefined) && !opts.urn) {
                throw new Error("Missing required property 'displayName'");
            }
            resourceInputs["compartmentId"] = args ? args.compartmentId : undefined;
            resourceInputs["definedTags"] = args ? args.definedTags : undefined;
            resourceInputs["displayName"] = args ? args.displayName : undefined;
            resourceInputs["freeformTags"] = args ? args.freeformTags : undefined;
            resourceInputs["isCompleted"] = args ? args.isCompleted : undefined;
            resourceInputs["replicationScheduleId"] = args ? args.replicationScheduleId : undefined;
            resourceInputs["lifecycleDetails"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["systemTags"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeUpdated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(Migration.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering Migration resources.
 */
export interface MigrationState {
    /**
     * (Updatable) Compartment identifier
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) Migration identifier
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. It exists only for cross-compatibility. Example: `{"bar-key": "value"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) Indicates whether migration is marked as complete.
     */
    isCompleted?: pulumi.Input<boolean>;
    /**
     * A message describing the current state in more detail. For example, it can be used to provide actionable information for a resource in Failed state.
     */
    lifecycleDetails?: pulumi.Input<string>;
    /**
     * (Updatable) Replication schedule identifier
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    replicationScheduleId?: pulumi.Input<string>;
    /**
     * The current state of migration.
     */
    state?: pulumi.Input<string>;
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    systemTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * The time when the migration project was created. An RFC3339 formatted datetime string
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The time when the migration project was updated. An RFC3339 formatted datetime string
     */
    timeUpdated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a Migration resource.
 */
export interface MigrationArgs {
    /**
     * (Updatable) Compartment identifier
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) Migration identifier
     */
    displayName: pulumi.Input<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. It exists only for cross-compatibility. Example: `{"bar-key": "value"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) Indicates whether migration is marked as complete.
     */
    isCompleted?: pulumi.Input<boolean>;
    /**
     * (Updatable) Replication schedule identifier
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    replicationScheduleId?: pulumi.Input<string>;
}
