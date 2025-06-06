// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Scheduling Plans in Oracle Cloud Infrastructure Database service.
 *
 * Lists the Scheduling Plan resources in the specified compartment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testSchedulingPlans = oci.Database.getSchedulingPlans({
 *     compartmentId: compartmentId,
 *     displayName: schedulingPlanDisplayName,
 *     id: schedulingPlanId,
 *     resourceId: testResource.id,
 *     schedulingPolicyId: testSchedulingPolicy.id,
 *     state: schedulingPlanState,
 * });
 * ```
 */
export function getSchedulingPlans(args: GetSchedulingPlansArgs, opts?: pulumi.InvokeOptions): Promise<GetSchedulingPlansResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Database/getSchedulingPlans:getSchedulingPlans", {
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
        "id": args.id,
        "resourceId": args.resourceId,
        "schedulingPolicyId": args.schedulingPolicyId,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getSchedulingPlans.
 */
export interface GetSchedulingPlansArgs {
    /**
     * The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    compartmentId: string;
    /**
     * A filter to return only resources that match the entire display name given. The match is not case sensitive.
     */
    displayName?: string;
    filters?: inputs.Database.GetSchedulingPlansFilter[];
    /**
     * A filter to return only resources that match the given Schedule Plan id exactly.
     */
    id?: string;
    /**
     * A filter to return only resources that match the given resource id exactly.
     */
    resourceId?: string;
    /**
     * A filter to return only resources that match the given scheduling policy id exactly.
     */
    schedulingPolicyId?: string;
    /**
     * A filter to return only resources that match the given lifecycle state exactly.
     */
    state?: string;
}

/**
 * A collection of values returned by getSchedulingPlans.
 */
export interface GetSchedulingPlansResult {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    readonly compartmentId: string;
    /**
     * The display name of the Scheduling Plan.
     */
    readonly displayName?: string;
    readonly filters?: outputs.Database.GetSchedulingPlansFilter[];
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Scheduling Plan.
     */
    readonly id?: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource.
     */
    readonly resourceId?: string;
    /**
     * The list of scheduling_plan_collection.
     */
    readonly schedulingPlanCollections: outputs.Database.GetSchedulingPlansSchedulingPlanCollection[];
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Scheduling Policy.
     */
    readonly schedulingPolicyId?: string;
    /**
     * The current state of the Scheduling Plan. Valid states are CREATING, NEEDS_ATTENTION, AVAILABLE, UPDATING, FAILED, DELETING and DELETED.
     */
    readonly state?: string;
}
/**
 * This data source provides the list of Scheduling Plans in Oracle Cloud Infrastructure Database service.
 *
 * Lists the Scheduling Plan resources in the specified compartment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testSchedulingPlans = oci.Database.getSchedulingPlans({
 *     compartmentId: compartmentId,
 *     displayName: schedulingPlanDisplayName,
 *     id: schedulingPlanId,
 *     resourceId: testResource.id,
 *     schedulingPolicyId: testSchedulingPolicy.id,
 *     state: schedulingPlanState,
 * });
 * ```
 */
export function getSchedulingPlansOutput(args: GetSchedulingPlansOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetSchedulingPlansResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Database/getSchedulingPlans:getSchedulingPlans", {
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
        "id": args.id,
        "resourceId": args.resourceId,
        "schedulingPolicyId": args.schedulingPolicyId,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getSchedulingPlans.
 */
export interface GetSchedulingPlansOutputArgs {
    /**
     * The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    compartmentId: pulumi.Input<string>;
    /**
     * A filter to return only resources that match the entire display name given. The match is not case sensitive.
     */
    displayName?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.Database.GetSchedulingPlansFilterArgs>[]>;
    /**
     * A filter to return only resources that match the given Schedule Plan id exactly.
     */
    id?: pulumi.Input<string>;
    /**
     * A filter to return only resources that match the given resource id exactly.
     */
    resourceId?: pulumi.Input<string>;
    /**
     * A filter to return only resources that match the given scheduling policy id exactly.
     */
    schedulingPolicyId?: pulumi.Input<string>;
    /**
     * A filter to return only resources that match the given lifecycle state exactly.
     */
    state?: pulumi.Input<string>;
}
