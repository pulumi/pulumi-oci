// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This resource provides the Table resource in Oracle Cloud Infrastructure NoSQL Database service.
 *
 * Create a new table.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testTable = new oci.nosql.Table("testTable", {
 *     compartmentId: _var.compartment_id,
 *     ddlStatement: _var.table_ddl_statement,
 *     tableLimits: {
 *         maxReadUnits: _var.table_table_limits_max_read_units,
 *         maxStorageInGbs: _var.table_table_limits_max_storage_in_gbs,
 *         maxWriteUnits: _var.table_table_limits_max_write_units,
 *         capacityMode: _var.table_table_limits_capacity_mode,
 *     },
 *     definedTags: _var.table_defined_tags,
 *     freeformTags: {
 *         "bar-key": "value",
 *     },
 *     isAutoReclaimable: _var.table_is_auto_reclaimable,
 * });
 * ```
 *
 * ## Import
 *
 * Tables can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:Nosql/table:Table test_table "id"
 * ```
 */
export class Table extends pulumi.CustomResource {
    /**
     * Get an existing Table resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: TableState, opts?: pulumi.CustomResourceOptions): Table {
        return new Table(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:Nosql/table:Table';

    /**
     * Returns true if the given object is an instance of Table.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is Table {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === Table.__pulumiType;
    }

    /**
     * (Updatable) Compartment Identifier.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * (Updatable) Complete CREATE TABLE DDL statement. When update ddl_statement, it should be ALTER TABLE DDL statement.
     */
    public readonly ddlStatement!: pulumi.Output<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{"foo-namespace": {"bar-key": "value"}}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * True if table can be reclaimed after an idle period.
     */
    public readonly isAutoReclaimable!: pulumi.Output<boolean>;
    /**
     * A message describing the current state in more detail.
     */
    public /*out*/ readonly lifecycleDetails!: pulumi.Output<string>;
    /**
     * Table name.
     */
    public readonly name!: pulumi.Output<string>;
    /**
     * The table schema information as a JSON object.
     */
    public /*out*/ readonly schemas!: pulumi.Output<outputs.Nosql.TableSchema[]>;
    /**
     * The state of a table.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * Read-only system tag. These predefined keys are scoped to namespaces.  At present the only supported namespace is `"orcl-cloud"`; and the only key in that namespace is `"free-tier-retained"`. Example: `{"orcl-cloud"": {"free-tier-retained": "true"}}`
     */
    public /*out*/ readonly systemTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * (Updatable) Throughput and storage limits configuration of a table.
     */
    public readonly tableLimits!: pulumi.Output<outputs.Nosql.TableTableLimits>;
    /**
     * The time the the table was created. An RFC3339 formatted datetime string.
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * If lifecycleState is INACTIVE, indicates when this table will be automatically removed. An RFC3339 formatted datetime string.
     */
    public /*out*/ readonly timeOfExpiration!: pulumi.Output<string>;
    /**
     * The time the the table's metadata was last updated. An RFC3339 formatted datetime string.
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;

    /**
     * Create a Table resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: TableArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: TableArgs | TableState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as TableState | undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["ddlStatement"] = state ? state.ddlStatement : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["isAutoReclaimable"] = state ? state.isAutoReclaimable : undefined;
            resourceInputs["lifecycleDetails"] = state ? state.lifecycleDetails : undefined;
            resourceInputs["name"] = state ? state.name : undefined;
            resourceInputs["schemas"] = state ? state.schemas : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["systemTags"] = state ? state.systemTags : undefined;
            resourceInputs["tableLimits"] = state ? state.tableLimits : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeOfExpiration"] = state ? state.timeOfExpiration : undefined;
            resourceInputs["timeUpdated"] = state ? state.timeUpdated : undefined;
        } else {
            const args = argsOrState as TableArgs | undefined;
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.ddlStatement === undefined) && !opts.urn) {
                throw new Error("Missing required property 'ddlStatement'");
            }
            if ((!args || args.tableLimits === undefined) && !opts.urn) {
                throw new Error("Missing required property 'tableLimits'");
            }
            resourceInputs["compartmentId"] = args ? args.compartmentId : undefined;
            resourceInputs["ddlStatement"] = args ? args.ddlStatement : undefined;
            resourceInputs["definedTags"] = args ? args.definedTags : undefined;
            resourceInputs["freeformTags"] = args ? args.freeformTags : undefined;
            resourceInputs["isAutoReclaimable"] = args ? args.isAutoReclaimable : undefined;
            resourceInputs["name"] = args ? args.name : undefined;
            resourceInputs["tableLimits"] = args ? args.tableLimits : undefined;
            resourceInputs["lifecycleDetails"] = undefined /*out*/;
            resourceInputs["schemas"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["systemTags"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeOfExpiration"] = undefined /*out*/;
            resourceInputs["timeUpdated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(Table.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering Table resources.
 */
export interface TableState {
    /**
     * (Updatable) Compartment Identifier.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) Complete CREATE TABLE DDL statement. When update ddl_statement, it should be ALTER TABLE DDL statement.
     */
    ddlStatement?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{"foo-namespace": {"bar-key": "value"}}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * True if table can be reclaimed after an idle period.
     */
    isAutoReclaimable?: pulumi.Input<boolean>;
    /**
     * A message describing the current state in more detail.
     */
    lifecycleDetails?: pulumi.Input<string>;
    /**
     * Table name.
     */
    name?: pulumi.Input<string>;
    /**
     * The table schema information as a JSON object.
     */
    schemas?: pulumi.Input<pulumi.Input<inputs.Nosql.TableSchema>[]>;
    /**
     * The state of a table.
     */
    state?: pulumi.Input<string>;
    /**
     * Read-only system tag. These predefined keys are scoped to namespaces.  At present the only supported namespace is `"orcl-cloud"`; and the only key in that namespace is `"free-tier-retained"`. Example: `{"orcl-cloud"": {"free-tier-retained": "true"}}`
     */
    systemTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) Throughput and storage limits configuration of a table.
     */
    tableLimits?: pulumi.Input<inputs.Nosql.TableTableLimits>;
    /**
     * The time the the table was created. An RFC3339 formatted datetime string.
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * If lifecycleState is INACTIVE, indicates when this table will be automatically removed. An RFC3339 formatted datetime string.
     */
    timeOfExpiration?: pulumi.Input<string>;
    /**
     * The time the the table's metadata was last updated. An RFC3339 formatted datetime string.
     */
    timeUpdated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a Table resource.
 */
export interface TableArgs {
    /**
     * (Updatable) Compartment Identifier.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) Complete CREATE TABLE DDL statement. When update ddl_statement, it should be ALTER TABLE DDL statement.
     */
    ddlStatement: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{"foo-namespace": {"bar-key": "value"}}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * True if table can be reclaimed after an idle period.
     */
    isAutoReclaimable?: pulumi.Input<boolean>;
    /**
     * Table name.
     */
    name?: pulumi.Input<string>;
    /**
     * (Updatable) Throughput and storage limits configuration of a table.
     */
    tableLimits: pulumi.Input<inputs.Nosql.TableTableLimits>;
}
