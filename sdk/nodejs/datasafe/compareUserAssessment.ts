// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This resource provides the Compare User Assessment resource in Oracle Cloud Infrastructure Data Safe service.
 *
 * Compares two user assessments. For this comparison, a user assessment can be a saved, a latest assessment, or a baseline.
 * As an example, it can be used to compare a user assessment saved or a latest assessment with a baseline.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testCompareUserAssessment = new oci.datasafe.CompareUserAssessment("testCompareUserAssessment", {
 *     comparisonUserAssessmentId: oci_data_safe_user_assessment.test_user_assessment.id,
 *     userAssessmentId: oci_data_safe_user_assessment.test_user_assessment.id,
 * });
 * ```
 *
 * ## Import
 *
 * CompareUserAssessment can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:DataSafe/compareUserAssessment:CompareUserAssessment test_compare_user_assessment "id"
 * ```
 */
export class CompareUserAssessment extends pulumi.CustomResource {
    /**
     * Get an existing CompareUserAssessment resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: CompareUserAssessmentState, opts?: pulumi.CustomResourceOptions): CompareUserAssessment {
        return new CompareUserAssessment(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:DataSafe/compareUserAssessment:CompareUserAssessment';

    /**
     * Returns true if the given object is an instance of CompareUserAssessment.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is CompareUserAssessment {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === CompareUserAssessment.__pulumiType;
    }

    /**
     * The OCID of the user assessment to be compared. You can compare with another user assessment, a latest assessment, or a baseline.
     */
    public readonly comparisonUserAssessmentId!: pulumi.Output<string>;
    /**
     * The OCID of the user assessment.
     */
    public readonly userAssessmentId!: pulumi.Output<string>;

    /**
     * Create a CompareUserAssessment resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: CompareUserAssessmentArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: CompareUserAssessmentArgs | CompareUserAssessmentState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as CompareUserAssessmentState | undefined;
            resourceInputs["comparisonUserAssessmentId"] = state ? state.comparisonUserAssessmentId : undefined;
            resourceInputs["userAssessmentId"] = state ? state.userAssessmentId : undefined;
        } else {
            const args = argsOrState as CompareUserAssessmentArgs | undefined;
            if ((!args || args.comparisonUserAssessmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'comparisonUserAssessmentId'");
            }
            if ((!args || args.userAssessmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'userAssessmentId'");
            }
            resourceInputs["comparisonUserAssessmentId"] = args ? args.comparisonUserAssessmentId : undefined;
            resourceInputs["userAssessmentId"] = args ? args.userAssessmentId : undefined;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(CompareUserAssessment.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering CompareUserAssessment resources.
 */
export interface CompareUserAssessmentState {
    /**
     * The OCID of the user assessment to be compared. You can compare with another user assessment, a latest assessment, or a baseline.
     */
    comparisonUserAssessmentId?: pulumi.Input<string>;
    /**
     * The OCID of the user assessment.
     */
    userAssessmentId?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a CompareUserAssessment resource.
 */
export interface CompareUserAssessmentArgs {
    /**
     * The OCID of the user assessment to be compared. You can compare with another user assessment, a latest assessment, or a baseline.
     */
    comparisonUserAssessmentId: pulumi.Input<string>;
    /**
     * The OCID of the user assessment.
     */
    userAssessmentId: pulumi.Input<string>;
}