// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This resource provides the Report Definition resource in Oracle Cloud Infrastructure Data Safe service.
 *
 * Creates a new report definition with parameters specified in the body. The report definition is stored in the specified compartment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testReportDefinition = new oci.datasafe.ReportDefinition("testReportDefinition", {
 *     columnFilters: [{
 *         expressions: _var.report_definition_column_filters_expressions,
 *         fieldName: _var.report_definition_column_filters_field_name,
 *         isEnabled: _var.report_definition_column_filters_is_enabled,
 *         isHidden: _var.report_definition_column_filters_is_hidden,
 *         operator: _var.report_definition_column_filters_operator,
 *     }],
 *     columnInfos: [{
 *         displayName: _var.report_definition_column_info_display_name,
 *         displayOrder: _var.report_definition_column_info_display_order,
 *         fieldName: _var.report_definition_column_info_field_name,
 *         isHidden: _var.report_definition_column_info_is_hidden,
 *         dataType: _var.report_definition_column_info_data_type,
 *     }],
 *     columnSortings: [{
 *         fieldName: _var.report_definition_column_sortings_field_name,
 *         isAscending: _var.report_definition_column_sortings_is_ascending,
 *         sortingOrder: _var.report_definition_column_sortings_sorting_order,
 *     }],
 *     compartmentId: _var.compartment_id,
 *     displayName: _var.report_definition_display_name,
 *     parentId: oci_data_safe_parent.test_parent.id,
 *     summaries: [{
 *         displayOrder: _var.report_definition_summary_display_order,
 *         name: _var.report_definition_summary_name,
 *         countOf: _var.report_definition_summary_count_of,
 *         groupByFieldName: _var.report_definition_summary_group_by_field_name,
 *         isHidden: _var.report_definition_summary_is_hidden,
 *         scimFilter: _var.report_definition_summary_scim_filter,
 *     }],
 *     definedTags: {
 *         "Operations.CostCenter": "42",
 *     },
 *     description: _var.report_definition_description,
 *     freeformTags: {
 *         Department: "Finance",
 *     },
 * });
 * ```
 *
 * ## Import
 *
 * ReportDefinitions can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:DataSafe/reportDefinition:ReportDefinition test_report_definition "id"
 * ```
 */
export class ReportDefinition extends pulumi.CustomResource {
    /**
     * Get an existing ReportDefinition resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: ReportDefinitionState, opts?: pulumi.CustomResourceOptions): ReportDefinition {
        return new ReportDefinition(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:DataSafe/reportDefinition:ReportDefinition';

    /**
     * Returns true if the given object is an instance of ReportDefinition.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is ReportDefinition {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === ReportDefinition.__pulumiType;
    }

    /**
     * Specifies the name of the category that this report belongs to.
     */
    public /*out*/ readonly category!: pulumi.Output<string>;
    /**
     * (Updatable) An array of column filter objects. A column Filter object stores all information about a column filter including field name, an operator, one or more expressions, if the filter is enabled, or if the filter is hidden.
     */
    public readonly columnFilters!: pulumi.Output<outputs.DataSafe.ReportDefinitionColumnFilter[]>;
    /**
     * (Updatable) An array of column objects in the order (left to right) displayed in the report. A column object stores all information about a column, including the name displayed on the UI, corresponding field name in the data source, data type of the column, and column visibility (if the column is visible to the user).
     */
    public readonly columnInfos!: pulumi.Output<outputs.DataSafe.ReportDefinitionColumnInfo[]>;
    /**
     * (Updatable) An array of column sorting objects. Each column sorting object stores the column name to be sorted and if the sorting is in ascending order; sorting is done by the first column in the array, then by the second column in the array, etc.
     */
    public readonly columnSortings!: pulumi.Output<outputs.DataSafe.ReportDefinitionColumnSorting[]>;
    /**
     * (Updatable) The OCID of the compartment containing the report definition.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * Specifies the name of a resource that provides data for the report. For example alerts, events.
     */
    public /*out*/ readonly dataSource!: pulumi.Output<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * (Updatable) A description of the report definition.
     */
    public readonly description!: pulumi.Output<string>;
    /**
     * (Updatable) Specifies the name of the report definition.
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * (Updatable) Specifies the order in which the summary must be displayed.
     */
    public /*out*/ readonly displayOrder!: pulumi.Output<number>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * Signifies whether the definition is seeded or user defined. Values can either be 'true' or 'false'.
     */
    public /*out*/ readonly isSeeded!: pulumi.Output<boolean>;
    /**
     * The OCID of the parent report definition.
     */
    public readonly parentId!: pulumi.Output<string>;
    /**
     * (Updatable) Additional scim filters used to get the specific summary.
     */
    public /*out*/ readonly scimFilter!: pulumi.Output<string>;
    /**
     * The current state of the report.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * (Updatable) An array of report summary objects in the order (left to right)  displayed in the report.  A  report summary object stores all information about summary of report to be displayed, including the name displayed on UI, the display order, corresponding group by and count of values, summary visibility (if the summary is visible to user).
     */
    public readonly summaries!: pulumi.Output<outputs.DataSafe.ReportDefinitionSummary[]>;
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    public /*out*/ readonly systemTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * Specifies the time at which the report definition was created.
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The date and time of the report definition update in Data Safe.
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;

    /**
     * Create a ReportDefinition resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: ReportDefinitionArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: ReportDefinitionArgs | ReportDefinitionState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as ReportDefinitionState | undefined;
            resourceInputs["category"] = state ? state.category : undefined;
            resourceInputs["columnFilters"] = state ? state.columnFilters : undefined;
            resourceInputs["columnInfos"] = state ? state.columnInfos : undefined;
            resourceInputs["columnSortings"] = state ? state.columnSortings : undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["dataSource"] = state ? state.dataSource : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["description"] = state ? state.description : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["displayOrder"] = state ? state.displayOrder : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["isSeeded"] = state ? state.isSeeded : undefined;
            resourceInputs["parentId"] = state ? state.parentId : undefined;
            resourceInputs["scimFilter"] = state ? state.scimFilter : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["summaries"] = state ? state.summaries : undefined;
            resourceInputs["systemTags"] = state ? state.systemTags : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeUpdated"] = state ? state.timeUpdated : undefined;
        } else {
            const args = argsOrState as ReportDefinitionArgs | undefined;
            if ((!args || args.columnFilters === undefined) && !opts.urn) {
                throw new Error("Missing required property 'columnFilters'");
            }
            if ((!args || args.columnInfos === undefined) && !opts.urn) {
                throw new Error("Missing required property 'columnInfos'");
            }
            if ((!args || args.columnSortings === undefined) && !opts.urn) {
                throw new Error("Missing required property 'columnSortings'");
            }
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.displayName === undefined) && !opts.urn) {
                throw new Error("Missing required property 'displayName'");
            }
            if ((!args || args.parentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'parentId'");
            }
            if ((!args || args.summaries === undefined) && !opts.urn) {
                throw new Error("Missing required property 'summaries'");
            }
            resourceInputs["columnFilters"] = args ? args.columnFilters : undefined;
            resourceInputs["columnInfos"] = args ? args.columnInfos : undefined;
            resourceInputs["columnSortings"] = args ? args.columnSortings : undefined;
            resourceInputs["compartmentId"] = args ? args.compartmentId : undefined;
            resourceInputs["definedTags"] = args ? args.definedTags : undefined;
            resourceInputs["description"] = args ? args.description : undefined;
            resourceInputs["displayName"] = args ? args.displayName : undefined;
            resourceInputs["freeformTags"] = args ? args.freeformTags : undefined;
            resourceInputs["parentId"] = args ? args.parentId : undefined;
            resourceInputs["summaries"] = args ? args.summaries : undefined;
            resourceInputs["category"] = undefined /*out*/;
            resourceInputs["dataSource"] = undefined /*out*/;
            resourceInputs["displayOrder"] = undefined /*out*/;
            resourceInputs["isSeeded"] = undefined /*out*/;
            resourceInputs["scimFilter"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["systemTags"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeUpdated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(ReportDefinition.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering ReportDefinition resources.
 */
export interface ReportDefinitionState {
    /**
     * Specifies the name of the category that this report belongs to.
     */
    category?: pulumi.Input<string>;
    /**
     * (Updatable) An array of column filter objects. A column Filter object stores all information about a column filter including field name, an operator, one or more expressions, if the filter is enabled, or if the filter is hidden.
     */
    columnFilters?: pulumi.Input<pulumi.Input<inputs.DataSafe.ReportDefinitionColumnFilter>[]>;
    /**
     * (Updatable) An array of column objects in the order (left to right) displayed in the report. A column object stores all information about a column, including the name displayed on the UI, corresponding field name in the data source, data type of the column, and column visibility (if the column is visible to the user).
     */
    columnInfos?: pulumi.Input<pulumi.Input<inputs.DataSafe.ReportDefinitionColumnInfo>[]>;
    /**
     * (Updatable) An array of column sorting objects. Each column sorting object stores the column name to be sorted and if the sorting is in ascending order; sorting is done by the first column in the array, then by the second column in the array, etc.
     */
    columnSortings?: pulumi.Input<pulumi.Input<inputs.DataSafe.ReportDefinitionColumnSorting>[]>;
    /**
     * (Updatable) The OCID of the compartment containing the report definition.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * Specifies the name of a resource that provides data for the report. For example alerts, events.
     */
    dataSource?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) A description of the report definition.
     */
    description?: pulumi.Input<string>;
    /**
     * (Updatable) Specifies the name of the report definition.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Specifies the order in which the summary must be displayed.
     */
    displayOrder?: pulumi.Input<number>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * Signifies whether the definition is seeded or user defined. Values can either be 'true' or 'false'.
     */
    isSeeded?: pulumi.Input<boolean>;
    /**
     * The OCID of the parent report definition.
     */
    parentId?: pulumi.Input<string>;
    /**
     * (Updatable) Additional scim filters used to get the specific summary.
     */
    scimFilter?: pulumi.Input<string>;
    /**
     * The current state of the report.
     */
    state?: pulumi.Input<string>;
    /**
     * (Updatable) An array of report summary objects in the order (left to right)  displayed in the report.  A  report summary object stores all information about summary of report to be displayed, including the name displayed on UI, the display order, corresponding group by and count of values, summary visibility (if the summary is visible to user).
     */
    summaries?: pulumi.Input<pulumi.Input<inputs.DataSafe.ReportDefinitionSummary>[]>;
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    systemTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * Specifies the time at which the report definition was created.
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The date and time of the report definition update in Data Safe.
     */
    timeUpdated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a ReportDefinition resource.
 */
export interface ReportDefinitionArgs {
    /**
     * (Updatable) An array of column filter objects. A column Filter object stores all information about a column filter including field name, an operator, one or more expressions, if the filter is enabled, or if the filter is hidden.
     */
    columnFilters: pulumi.Input<pulumi.Input<inputs.DataSafe.ReportDefinitionColumnFilter>[]>;
    /**
     * (Updatable) An array of column objects in the order (left to right) displayed in the report. A column object stores all information about a column, including the name displayed on the UI, corresponding field name in the data source, data type of the column, and column visibility (if the column is visible to the user).
     */
    columnInfos: pulumi.Input<pulumi.Input<inputs.DataSafe.ReportDefinitionColumnInfo>[]>;
    /**
     * (Updatable) An array of column sorting objects. Each column sorting object stores the column name to be sorted and if the sorting is in ascending order; sorting is done by the first column in the array, then by the second column in the array, etc.
     */
    columnSortings: pulumi.Input<pulumi.Input<inputs.DataSafe.ReportDefinitionColumnSorting>[]>;
    /**
     * (Updatable) The OCID of the compartment containing the report definition.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) A description of the report definition.
     */
    description?: pulumi.Input<string>;
    /**
     * (Updatable) Specifies the name of the report definition.
     */
    displayName: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * The OCID of the parent report definition.
     */
    parentId: pulumi.Input<string>;
    /**
     * (Updatable) An array of report summary objects in the order (left to right)  displayed in the report.  A  report summary object stores all information about summary of report to be displayed, including the name displayed on UI, the display order, corresponding group by and count of values, summary visibility (if the summary is visible to user).
     */
    summaries: pulumi.Input<pulumi.Input<inputs.DataSafe.ReportDefinitionSummary>[]>;
}