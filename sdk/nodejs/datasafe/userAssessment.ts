// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This resource provides the User Assessment resource in Oracle Cloud Infrastructure Data Safe service.
 *
 * Creates a new saved user assessment for one or multiple targets in a compartment. It saves the latest assessments in the
 * specified compartment. If a scheduled is passed in, this operation persists the latest assessments that exist at the defined
 * date and time, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testUserAssessment = new oci.datasafe.UserAssessment("testUserAssessment", {
 *     compartmentId: _var.compartment_id,
 *     targetId: oci_cloud_guard_target.test_target.id,
 *     definedTags: {
 *         "Operations.CostCenter": "42",
 *     },
 *     description: _var.user_assessment_description,
 *     displayName: _var.user_assessment_display_name,
 *     freeformTags: {
 *         Department: "Finance",
 *     },
 *     schedule: _var.user_assessment_schedule,
 * });
 * ```
 *
 * ## Import
 *
 * UserAssessments can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:DataSafe/userAssessment:UserAssessment test_user_assessment "id"
 * ```
 */
export class UserAssessment extends pulumi.CustomResource {
    /**
     * Get an existing UserAssessment resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: UserAssessmentState, opts?: pulumi.CustomResourceOptions): UserAssessment {
        return new UserAssessment(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:DataSafe/userAssessment:UserAssessment';

    /**
     * Returns true if the given object is an instance of UserAssessment.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is UserAssessment {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === UserAssessment.__pulumiType;
    }

    /**
     * (Updatable) The OCID of the compartment that contains the user assessment.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * (Updatable) The description of the user assessment.
     */
    public readonly description!: pulumi.Output<string>;
    /**
     * (Updatable) The display name of the user assessment.
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * List containing maps as values. Example: `{"Operations": [ {"CostCenter": "42"} ] }`
     */
    public /*out*/ readonly ignoredAssessmentIds!: pulumi.Output<string[]>;
    /**
     * List containing maps as values. Example: `{"Operations": [ {"CostCenter": "42"} ] }`
     */
    public /*out*/ readonly ignoredTargets!: pulumi.Output<outputs.DataSafe.UserAssessmentIgnoredTarget[]>;
    /**
     * Indicates if the user assessment is set as a baseline. This is applicable only to saved user assessments.
     */
    public /*out*/ readonly isBaseline!: pulumi.Output<boolean>;
    /**
     * Indicates if the user assessment deviates from the baseline.
     */
    public /*out*/ readonly isDeviatedFromBaseline!: pulumi.Output<boolean>;
    /**
     * The OCID of the last user assessment baseline against which the latest assessment was compared.
     */
    public /*out*/ readonly lastComparedBaselineId!: pulumi.Output<string>;
    /**
     * Details about the current state of the user assessment.
     */
    public /*out*/ readonly lifecycleDetails!: pulumi.Output<string>;
    /**
     * (Updatable) To schedule the assessment for saving periodically, specify the schedule in this attribute. Create or schedule one assessment per compartment. If not defined, the assessment runs immediately. Format - <version-string>;<version-specific-schedule>
     */
    public readonly schedule!: pulumi.Output<string>;
    /**
     * The OCID of the user assessment that is responsible for creating this scheduled save assessment.
     */
    public /*out*/ readonly scheduleAssessmentId!: pulumi.Output<string>;
    /**
     * The current state of the user assessment.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * Map that contains maps of values. Example: `{"Operations": {"CostCenter": "42"}}`
     */
    public /*out*/ readonly statistics!: pulumi.Output<string>;
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    public /*out*/ readonly systemTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * The OCID of the target database on which the user assessment is to be run.
     */
    public readonly targetId!: pulumi.Output<string>;
    /**
     * Array of database target OCIDs.
     */
    public /*out*/ readonly targetIds!: pulumi.Output<string[]>;
    /**
     * The date and time when the user assessment was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The last date and time when the user assessment was updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;
    /**
     * Indicates whether the user assessment was created by system or user.
     */
    public /*out*/ readonly triggeredBy!: pulumi.Output<string>;
    /**
     * Type of user assessment. The possible types are:
     */
    public /*out*/ readonly type!: pulumi.Output<string>;

    /**
     * Create a UserAssessment resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: UserAssessmentArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: UserAssessmentArgs | UserAssessmentState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as UserAssessmentState | undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["description"] = state ? state.description : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["ignoredAssessmentIds"] = state ? state.ignoredAssessmentIds : undefined;
            resourceInputs["ignoredTargets"] = state ? state.ignoredTargets : undefined;
            resourceInputs["isBaseline"] = state ? state.isBaseline : undefined;
            resourceInputs["isDeviatedFromBaseline"] = state ? state.isDeviatedFromBaseline : undefined;
            resourceInputs["lastComparedBaselineId"] = state ? state.lastComparedBaselineId : undefined;
            resourceInputs["lifecycleDetails"] = state ? state.lifecycleDetails : undefined;
            resourceInputs["schedule"] = state ? state.schedule : undefined;
            resourceInputs["scheduleAssessmentId"] = state ? state.scheduleAssessmentId : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["statistics"] = state ? state.statistics : undefined;
            resourceInputs["systemTags"] = state ? state.systemTags : undefined;
            resourceInputs["targetId"] = state ? state.targetId : undefined;
            resourceInputs["targetIds"] = state ? state.targetIds : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeUpdated"] = state ? state.timeUpdated : undefined;
            resourceInputs["triggeredBy"] = state ? state.triggeredBy : undefined;
            resourceInputs["type"] = state ? state.type : undefined;
        } else {
            const args = argsOrState as UserAssessmentArgs | undefined;
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.targetId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'targetId'");
            }
            resourceInputs["compartmentId"] = args ? args.compartmentId : undefined;
            resourceInputs["definedTags"] = args ? args.definedTags : undefined;
            resourceInputs["description"] = args ? args.description : undefined;
            resourceInputs["displayName"] = args ? args.displayName : undefined;
            resourceInputs["freeformTags"] = args ? args.freeformTags : undefined;
            resourceInputs["schedule"] = args ? args.schedule : undefined;
            resourceInputs["targetId"] = args ? args.targetId : undefined;
            resourceInputs["ignoredAssessmentIds"] = undefined /*out*/;
            resourceInputs["ignoredTargets"] = undefined /*out*/;
            resourceInputs["isBaseline"] = undefined /*out*/;
            resourceInputs["isDeviatedFromBaseline"] = undefined /*out*/;
            resourceInputs["lastComparedBaselineId"] = undefined /*out*/;
            resourceInputs["lifecycleDetails"] = undefined /*out*/;
            resourceInputs["scheduleAssessmentId"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["statistics"] = undefined /*out*/;
            resourceInputs["systemTags"] = undefined /*out*/;
            resourceInputs["targetIds"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeUpdated"] = undefined /*out*/;
            resourceInputs["triggeredBy"] = undefined /*out*/;
            resourceInputs["type"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(UserAssessment.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering UserAssessment resources.
 */
export interface UserAssessmentState {
    /**
     * (Updatable) The OCID of the compartment that contains the user assessment.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) The description of the user assessment.
     */
    description?: pulumi.Input<string>;
    /**
     * (Updatable) The display name of the user assessment.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * List containing maps as values. Example: `{"Operations": [ {"CostCenter": "42"} ] }`
     */
    ignoredAssessmentIds?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * List containing maps as values. Example: `{"Operations": [ {"CostCenter": "42"} ] }`
     */
    ignoredTargets?: pulumi.Input<pulumi.Input<inputs.DataSafe.UserAssessmentIgnoredTarget>[]>;
    /**
     * Indicates if the user assessment is set as a baseline. This is applicable only to saved user assessments.
     */
    isBaseline?: pulumi.Input<boolean>;
    /**
     * Indicates if the user assessment deviates from the baseline.
     */
    isDeviatedFromBaseline?: pulumi.Input<boolean>;
    /**
     * The OCID of the last user assessment baseline against which the latest assessment was compared.
     */
    lastComparedBaselineId?: pulumi.Input<string>;
    /**
     * Details about the current state of the user assessment.
     */
    lifecycleDetails?: pulumi.Input<string>;
    /**
     * (Updatable) To schedule the assessment for saving periodically, specify the schedule in this attribute. Create or schedule one assessment per compartment. If not defined, the assessment runs immediately. Format - <version-string>;<version-specific-schedule>
     */
    schedule?: pulumi.Input<string>;
    /**
     * The OCID of the user assessment that is responsible for creating this scheduled save assessment.
     */
    scheduleAssessmentId?: pulumi.Input<string>;
    /**
     * The current state of the user assessment.
     */
    state?: pulumi.Input<string>;
    /**
     * Map that contains maps of values. Example: `{"Operations": {"CostCenter": "42"}}`
     */
    statistics?: pulumi.Input<string>;
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    systemTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * The OCID of the target database on which the user assessment is to be run.
     */
    targetId?: pulumi.Input<string>;
    /**
     * Array of database target OCIDs.
     */
    targetIds?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * The date and time when the user assessment was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The last date and time when the user assessment was updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     */
    timeUpdated?: pulumi.Input<string>;
    /**
     * Indicates whether the user assessment was created by system or user.
     */
    triggeredBy?: pulumi.Input<string>;
    /**
     * Type of user assessment. The possible types are:
     */
    type?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a UserAssessment resource.
 */
export interface UserAssessmentArgs {
    /**
     * (Updatable) The OCID of the compartment that contains the user assessment.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) The description of the user assessment.
     */
    description?: pulumi.Input<string>;
    /**
     * (Updatable) The display name of the user assessment.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) To schedule the assessment for saving periodically, specify the schedule in this attribute. Create or schedule one assessment per compartment. If not defined, the assessment runs immediately. Format - <version-string>;<version-specific-schedule>
     */
    schedule?: pulumi.Input<string>;
    /**
     * The OCID of the target database on which the user assessment is to be run.
     */
    targetId: pulumi.Input<string>;
}