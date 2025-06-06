// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This resource provides the Dr Plan resource in Oracle Cloud Infrastructure Disaster Recovery service.
 *
 * Create a DR plan of the specified DR plan type.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDrPlan = new oci.disasterrecovery.DrPlan("test_dr_plan", {
 *     displayName: drPlanDisplayName,
 *     drProtectionGroupId: testDrProtectionGroup.id,
 *     type: drPlanType,
 *     definedTags: {
 *         "Operations.CostCenter": "42",
 *     },
 *     freeformTags: {
 *         Department: "Finance",
 *     },
 *     sourcePlanId: testSourcePlan.id,
 * });
 * ```
 *
 * ## Import
 *
 * DrPlans can be imported using the `id`, e.g.
 *
 * ```sh
 * $ pulumi import oci:DisasterRecovery/drPlan:DrPlan test_dr_plan "id"
 * ```
 */
export class DrPlan extends pulumi.CustomResource {
    /**
     * Get an existing DrPlan resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: DrPlanState, opts?: pulumi.CustomResourceOptions): DrPlan {
        return new DrPlan(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:DisasterRecovery/drPlan:DrPlan';

    /**
     * Returns true if the given object is an instance of DrPlan.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is DrPlan {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === DrPlan.__pulumiType;
    }

    /**
     * The OCID of the compartment containing the DR plan.  Example: `ocid1.compartment.oc1..uniqueID`
     */
    public /*out*/ readonly compartmentId!: pulumi.Output<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{"Operations.CostCenter": "42"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * (Updatable) The display name of the DR plan being created.  Example: `EBS Switchover PHX to IAD`
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * The OCID of the DR protection group to which this DR plan belongs.  Example: `ocid1.drprotectiongroup.oc1..uniqueID`
     */
    public readonly drProtectionGroupId!: pulumi.Output<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  Example: `{"Department": "Finance"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * A message describing the DR plan's current state in more detail.
     */
    public /*out*/ readonly lifeCycleDetails!: pulumi.Output<string>;
    /**
     * The current state of the DR plan.
     */
    public /*out*/ readonly lifecycleSubState!: pulumi.Output<string>;
    /**
     * The OCID of the peer DR protection group associated with this plan's DR protection group.  Example: `ocid1.drprotectiongroup.oc1..uniqueID`
     */
    public /*out*/ readonly peerDrProtectionGroupId!: pulumi.Output<string>;
    /**
     * The region of the peer DR protection group associated with this plan's DR protection group.  Example: `us-ashburn-1`
     */
    public /*out*/ readonly peerRegion!: pulumi.Output<string>;
    /**
     * The list of groups in this DR plan.
     */
    public /*out*/ readonly planGroups!: pulumi.Output<outputs.DisasterRecovery.DrPlanPlanGroup[]>;
    /**
     * (Updatable) An optional property when incremented triggers Refresh. Could be set to any integer value.
     */
    public readonly refreshTrigger!: pulumi.Output<number | undefined>;
    /**
     * The OCID of the source DR plan that should be cloned.  Example: `ocid1.drplan.oc1..uniqueID`
     */
    public readonly sourcePlanId!: pulumi.Output<string>;
    /**
     * The current state of the DR plan.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    public /*out*/ readonly systemTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * The date and time the DR plan was created. An RFC3339 formatted datetime string.  Example: `2019-03-29T09:36:42Z`
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The date and time the DR plan was updated. An RFC3339 formatted datetime string.  Example: `2019-03-29T09:36:42Z`
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;
    /**
     * The type of DR plan to be created.
     */
    public readonly type!: pulumi.Output<string>;
    /**
     * (Updatable) An optional property when incremented triggers Verify. Could be set to any integer value.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    public readonly verifyTrigger!: pulumi.Output<number | undefined>;

    /**
     * Create a DrPlan resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: DrPlanArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: DrPlanArgs | DrPlanState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as DrPlanState | undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["drProtectionGroupId"] = state ? state.drProtectionGroupId : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["lifeCycleDetails"] = state ? state.lifeCycleDetails : undefined;
            resourceInputs["lifecycleSubState"] = state ? state.lifecycleSubState : undefined;
            resourceInputs["peerDrProtectionGroupId"] = state ? state.peerDrProtectionGroupId : undefined;
            resourceInputs["peerRegion"] = state ? state.peerRegion : undefined;
            resourceInputs["planGroups"] = state ? state.planGroups : undefined;
            resourceInputs["refreshTrigger"] = state ? state.refreshTrigger : undefined;
            resourceInputs["sourcePlanId"] = state ? state.sourcePlanId : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["systemTags"] = state ? state.systemTags : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeUpdated"] = state ? state.timeUpdated : undefined;
            resourceInputs["type"] = state ? state.type : undefined;
            resourceInputs["verifyTrigger"] = state ? state.verifyTrigger : undefined;
        } else {
            const args = argsOrState as DrPlanArgs | undefined;
            if ((!args || args.displayName === undefined) && !opts.urn) {
                throw new Error("Missing required property 'displayName'");
            }
            if ((!args || args.drProtectionGroupId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'drProtectionGroupId'");
            }
            if ((!args || args.type === undefined) && !opts.urn) {
                throw new Error("Missing required property 'type'");
            }
            resourceInputs["definedTags"] = args ? args.definedTags : undefined;
            resourceInputs["displayName"] = args ? args.displayName : undefined;
            resourceInputs["drProtectionGroupId"] = args ? args.drProtectionGroupId : undefined;
            resourceInputs["freeformTags"] = args ? args.freeformTags : undefined;
            resourceInputs["refreshTrigger"] = args ? args.refreshTrigger : undefined;
            resourceInputs["sourcePlanId"] = args ? args.sourcePlanId : undefined;
            resourceInputs["type"] = args ? args.type : undefined;
            resourceInputs["verifyTrigger"] = args ? args.verifyTrigger : undefined;
            resourceInputs["compartmentId"] = undefined /*out*/;
            resourceInputs["lifeCycleDetails"] = undefined /*out*/;
            resourceInputs["lifecycleSubState"] = undefined /*out*/;
            resourceInputs["peerDrProtectionGroupId"] = undefined /*out*/;
            resourceInputs["peerRegion"] = undefined /*out*/;
            resourceInputs["planGroups"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["systemTags"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeUpdated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(DrPlan.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering DrPlan resources.
 */
export interface DrPlanState {
    /**
     * The OCID of the compartment containing the DR plan.  Example: `ocid1.compartment.oc1..uniqueID`
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) The display name of the DR plan being created.  Example: `EBS Switchover PHX to IAD`
     */
    displayName?: pulumi.Input<string>;
    /**
     * The OCID of the DR protection group to which this DR plan belongs.  Example: `ocid1.drprotectiongroup.oc1..uniqueID`
     */
    drProtectionGroupId?: pulumi.Input<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * A message describing the DR plan's current state in more detail.
     */
    lifeCycleDetails?: pulumi.Input<string>;
    /**
     * The current state of the DR plan.
     */
    lifecycleSubState?: pulumi.Input<string>;
    /**
     * The OCID of the peer DR protection group associated with this plan's DR protection group.  Example: `ocid1.drprotectiongroup.oc1..uniqueID`
     */
    peerDrProtectionGroupId?: pulumi.Input<string>;
    /**
     * The region of the peer DR protection group associated with this plan's DR protection group.  Example: `us-ashburn-1`
     */
    peerRegion?: pulumi.Input<string>;
    /**
     * The list of groups in this DR plan.
     */
    planGroups?: pulumi.Input<pulumi.Input<inputs.DisasterRecovery.DrPlanPlanGroup>[]>;
    /**
     * (Updatable) An optional property when incremented triggers Refresh. Could be set to any integer value.
     */
    refreshTrigger?: pulumi.Input<number>;
    /**
     * The OCID of the source DR plan that should be cloned.  Example: `ocid1.drplan.oc1..uniqueID`
     */
    sourcePlanId?: pulumi.Input<string>;
    /**
     * The current state of the DR plan.
     */
    state?: pulumi.Input<string>;
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    systemTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * The date and time the DR plan was created. An RFC3339 formatted datetime string.  Example: `2019-03-29T09:36:42Z`
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The date and time the DR plan was updated. An RFC3339 formatted datetime string.  Example: `2019-03-29T09:36:42Z`
     */
    timeUpdated?: pulumi.Input<string>;
    /**
     * The type of DR plan to be created.
     */
    type?: pulumi.Input<string>;
    /**
     * (Updatable) An optional property when incremented triggers Verify. Could be set to any integer value.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    verifyTrigger?: pulumi.Input<number>;
}

/**
 * The set of arguments for constructing a DrPlan resource.
 */
export interface DrPlanArgs {
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) The display name of the DR plan being created.  Example: `EBS Switchover PHX to IAD`
     */
    displayName: pulumi.Input<string>;
    /**
     * The OCID of the DR protection group to which this DR plan belongs.  Example: `ocid1.drprotectiongroup.oc1..uniqueID`
     */
    drProtectionGroupId: pulumi.Input<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) An optional property when incremented triggers Refresh. Could be set to any integer value.
     */
    refreshTrigger?: pulumi.Input<number>;
    /**
     * The OCID of the source DR plan that should be cloned.  Example: `ocid1.drplan.oc1..uniqueID`
     */
    sourcePlanId?: pulumi.Input<string>;
    /**
     * The type of DR plan to be created.
     */
    type: pulumi.Input<string>;
    /**
     * (Updatable) An optional property when incremented triggers Verify. Could be set to any integer value.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    verifyTrigger?: pulumi.Input<number>;
}
