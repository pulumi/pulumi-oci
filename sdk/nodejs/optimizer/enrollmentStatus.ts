// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This resource provides the Enrollment Status resource in Oracle Cloud Infrastructure Optimizer service.
 *
 * Updates the enrollment status of the tenancy.
 *
 * ## Import
 *
 * EnrollmentStatus can be imported using the `id`, e.g.
 *
 * ```sh
 * $ pulumi import oci:Optimizer/enrollmentStatus:EnrollmentStatus test_enrollment_status "id"
 * ```
 */
export class EnrollmentStatus extends pulumi.CustomResource {
    /**
     * Get an existing EnrollmentStatus resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: EnrollmentStatusState, opts?: pulumi.CustomResourceOptions): EnrollmentStatus {
        return new EnrollmentStatus(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:Optimizer/enrollmentStatus:EnrollmentStatus';

    /**
     * Returns true if the given object is an instance of EnrollmentStatus.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is EnrollmentStatus {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === EnrollmentStatus.__pulumiType;
    }

    /**
     * The OCID of the compartment.
     */
    public /*out*/ readonly compartmentId!: pulumi.Output<string>;
    /**
     * The unique OCID associated with the enrollment status.
     */
    public readonly enrollmentStatusId!: pulumi.Output<string>;
    /**
     * The enrollment status' current state.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * (Updatable) The Cloud Advisor enrollment status.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    public readonly status!: pulumi.Output<string>;
    /**
     * The reason for the enrollment status of the tenancy.
     */
    public /*out*/ readonly statusReason!: pulumi.Output<string>;
    /**
     * The date and time the enrollment status was created, in the format defined by RFC3339.
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The date and time the enrollment status was last updated, in the format defined by RFC3339.
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;

    /**
     * Create a EnrollmentStatus resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: EnrollmentStatusArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: EnrollmentStatusArgs | EnrollmentStatusState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as EnrollmentStatusState | undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["enrollmentStatusId"] = state ? state.enrollmentStatusId : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["status"] = state ? state.status : undefined;
            resourceInputs["statusReason"] = state ? state.statusReason : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeUpdated"] = state ? state.timeUpdated : undefined;
        } else {
            const args = argsOrState as EnrollmentStatusArgs | undefined;
            if ((!args || args.enrollmentStatusId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'enrollmentStatusId'");
            }
            if ((!args || args.status === undefined) && !opts.urn) {
                throw new Error("Missing required property 'status'");
            }
            resourceInputs["enrollmentStatusId"] = args ? args.enrollmentStatusId : undefined;
            resourceInputs["status"] = args ? args.status : undefined;
            resourceInputs["compartmentId"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["statusReason"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeUpdated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(EnrollmentStatus.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering EnrollmentStatus resources.
 */
export interface EnrollmentStatusState {
    /**
     * The OCID of the compartment.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * The unique OCID associated with the enrollment status.
     */
    enrollmentStatusId?: pulumi.Input<string>;
    /**
     * The enrollment status' current state.
     */
    state?: pulumi.Input<string>;
    /**
     * (Updatable) The Cloud Advisor enrollment status.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    status?: pulumi.Input<string>;
    /**
     * The reason for the enrollment status of the tenancy.
     */
    statusReason?: pulumi.Input<string>;
    /**
     * The date and time the enrollment status was created, in the format defined by RFC3339.
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The date and time the enrollment status was last updated, in the format defined by RFC3339.
     */
    timeUpdated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a EnrollmentStatus resource.
 */
export interface EnrollmentStatusArgs {
    /**
     * The unique OCID associated with the enrollment status.
     */
    enrollmentStatusId: pulumi.Input<string>;
    /**
     * (Updatable) The Cloud Advisor enrollment status.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    status: pulumi.Input<string>;
}
