// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This resource provides the Data Mask Rule resource in Oracle Cloud Infrastructure Cloud Guard service.
 *
 * Creates a new Data Mask Rule Definition
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDataMaskRule = new oci.cloudguard.DataMaskRule("testDataMaskRule", {
 *     compartmentId: _var.compartment_id,
 *     dataMaskCategories: _var.data_mask_rule_data_mask_categories,
 *     displayName: _var.data_mask_rule_display_name,
 *     iamGroupId: oci_identity_group.test_group.id,
 *     targetSelected: {
 *         kind: _var.data_mask_rule_target_selected_kind,
 *         values: _var.data_mask_rule_target_selected_values,
 *     },
 *     dataMaskRuleStatus: _var.data_mask_rule_data_mask_rule_status,
 *     definedTags: {
 *         "foo-namespace.bar-key": "value",
 *     },
 *     description: _var.data_mask_rule_description,
 *     freeformTags: {
 *         "bar-key": "value",
 *     },
 *     state: _var.data_mask_rule_state,
 * });
 * ```
 *
 * ## Import
 *
 * DataMaskRules can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:CloudGuard/dataMaskRule:DataMaskRule test_data_mask_rule "id"
 * ```
 */
export class DataMaskRule extends pulumi.CustomResource {
    /**
     * Get an existing DataMaskRule resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: DataMaskRuleState, opts?: pulumi.CustomResourceOptions): DataMaskRule {
        return new DataMaskRule(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:CloudGuard/dataMaskRule:DataMaskRule';

    /**
     * Returns true if the given object is an instance of DataMaskRule.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is DataMaskRule {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === DataMaskRule.__pulumiType;
    }

    /**
     * (Updatable) Compartment Identifier where the resource is created
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * (Updatable) Data Mask Categories
     */
    public readonly dataMaskCategories!: pulumi.Output<string[]>;
    /**
     * (Updatable) The status of the dataMaskRule.
     */
    public readonly dataMaskRuleStatus!: pulumi.Output<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * The data mask rule description. Avoid entering confidential information.
     */
    public readonly description!: pulumi.Output<string>;
    /**
     * (Updatable) Data mask rule name.
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * (Updatable) IAM Group id associated with the data mask rule
     */
    public readonly iamGroupId!: pulumi.Output<string>;
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     */
    public /*out*/ readonly lifecyleDetails!: pulumi.Output<string>;
    /**
     * The current state of the DataMaskRule.
     */
    public readonly state!: pulumi.Output<string>;
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    public /*out*/ readonly systemTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * (Updatable) Target Selection eg select ALL or select on basis of TargetResourceTypes or TargetIds.
     */
    public readonly targetSelected!: pulumi.Output<outputs.CloudGuard.DataMaskRuleTargetSelected>;
    /**
     * The date and time the target was created. Format defined by RFC3339.
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The date and time the target was updated. Format defined by RFC3339.
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;

    /**
     * Create a DataMaskRule resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: DataMaskRuleArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: DataMaskRuleArgs | DataMaskRuleState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as DataMaskRuleState | undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["dataMaskCategories"] = state ? state.dataMaskCategories : undefined;
            resourceInputs["dataMaskRuleStatus"] = state ? state.dataMaskRuleStatus : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["description"] = state ? state.description : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["iamGroupId"] = state ? state.iamGroupId : undefined;
            resourceInputs["lifecyleDetails"] = state ? state.lifecyleDetails : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["systemTags"] = state ? state.systemTags : undefined;
            resourceInputs["targetSelected"] = state ? state.targetSelected : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeUpdated"] = state ? state.timeUpdated : undefined;
        } else {
            const args = argsOrState as DataMaskRuleArgs | undefined;
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.dataMaskCategories === undefined) && !opts.urn) {
                throw new Error("Missing required property 'dataMaskCategories'");
            }
            if ((!args || args.displayName === undefined) && !opts.urn) {
                throw new Error("Missing required property 'displayName'");
            }
            if ((!args || args.iamGroupId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'iamGroupId'");
            }
            if ((!args || args.targetSelected === undefined) && !opts.urn) {
                throw new Error("Missing required property 'targetSelected'");
            }
            resourceInputs["compartmentId"] = args ? args.compartmentId : undefined;
            resourceInputs["dataMaskCategories"] = args ? args.dataMaskCategories : undefined;
            resourceInputs["dataMaskRuleStatus"] = args ? args.dataMaskRuleStatus : undefined;
            resourceInputs["definedTags"] = args ? args.definedTags : undefined;
            resourceInputs["description"] = args ? args.description : undefined;
            resourceInputs["displayName"] = args ? args.displayName : undefined;
            resourceInputs["freeformTags"] = args ? args.freeformTags : undefined;
            resourceInputs["iamGroupId"] = args ? args.iamGroupId : undefined;
            resourceInputs["state"] = args ? args.state : undefined;
            resourceInputs["targetSelected"] = args ? args.targetSelected : undefined;
            resourceInputs["lifecyleDetails"] = undefined /*out*/;
            resourceInputs["systemTags"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeUpdated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(DataMaskRule.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering DataMaskRule resources.
 */
export interface DataMaskRuleState {
    /**
     * (Updatable) Compartment Identifier where the resource is created
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) Data Mask Categories
     */
    dataMaskCategories?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * (Updatable) The status of the dataMaskRule.
     */
    dataMaskRuleStatus?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * The data mask rule description. Avoid entering confidential information.
     */
    description?: pulumi.Input<string>;
    /**
     * (Updatable) Data mask rule name.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) IAM Group id associated with the data mask rule
     */
    iamGroupId?: pulumi.Input<string>;
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     */
    lifecyleDetails?: pulumi.Input<string>;
    /**
     * The current state of the DataMaskRule.
     */
    state?: pulumi.Input<string>;
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    systemTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) Target Selection eg select ALL or select on basis of TargetResourceTypes or TargetIds.
     */
    targetSelected?: pulumi.Input<inputs.CloudGuard.DataMaskRuleTargetSelected>;
    /**
     * The date and time the target was created. Format defined by RFC3339.
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The date and time the target was updated. Format defined by RFC3339.
     */
    timeUpdated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a DataMaskRule resource.
 */
export interface DataMaskRuleArgs {
    /**
     * (Updatable) Compartment Identifier where the resource is created
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) Data Mask Categories
     */
    dataMaskCategories: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * (Updatable) The status of the dataMaskRule.
     */
    dataMaskRuleStatus?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * The data mask rule description. Avoid entering confidential information.
     */
    description?: pulumi.Input<string>;
    /**
     * (Updatable) Data mask rule name.
     */
    displayName: pulumi.Input<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) IAM Group id associated with the data mask rule
     */
    iamGroupId: pulumi.Input<string>;
    /**
     * The current state of the DataMaskRule.
     */
    state?: pulumi.Input<string>;
    /**
     * (Updatable) Target Selection eg select ALL or select on basis of TargetResourceTypes or TargetIds.
     */
    targetSelected: pulumi.Input<inputs.CloudGuard.DataMaskRuleTargetSelected>;
}