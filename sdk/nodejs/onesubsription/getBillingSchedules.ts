// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Billing Schedules in Oracle Cloud Infrastructure Onesubscription service.
 *
 * This list API returns all billing schedules for given subscription id and
 * for a particular Subscribed Service if provided
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testBillingSchedules = oci.OneSubsription.getBillingSchedules({
 *     compartmentId: _var.compartment_id,
 *     subscriptionId: oci_onesubscription_subscription.test_subscription.id,
 *     subscribedServiceId: oci_onesubscription_subscribed_service.test_subscribed_service.id,
 * });
 * ```
 */
export function getBillingSchedules(args: GetBillingSchedulesArgs, opts?: pulumi.InvokeOptions): Promise<GetBillingSchedulesResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:OneSubsription/getBillingSchedules:getBillingSchedules", {
        "compartmentId": args.compartmentId,
        "filters": args.filters,
        "subscribedServiceId": args.subscribedServiceId,
        "subscriptionId": args.subscriptionId,
    }, opts);
}

/**
 * A collection of arguments for invoking getBillingSchedules.
 */
export interface GetBillingSchedulesArgs {
    /**
     * The OCID of the root compartment.
     */
    compartmentId: string;
    filters?: inputs.OneSubsription.GetBillingSchedulesFilter[];
    /**
     * This param is used to get only the billing schedules for a particular Subscribed Service
     */
    subscribedServiceId?: string;
    /**
     * This param is used to get only the billing schedules for a particular Subscription Id
     */
    subscriptionId: string;
}

/**
 * A collection of values returned by getBillingSchedules.
 */
export interface GetBillingSchedulesResult {
    /**
     * The list of billing_schedules.
     */
    readonly billingSchedules: outputs.OneSubsription.GetBillingSchedulesBillingSchedule[];
    readonly compartmentId: string;
    readonly filters?: outputs.OneSubsription.GetBillingSchedulesFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * SPM internal Subscribed Service ID
     */
    readonly subscribedServiceId?: string;
    readonly subscriptionId: string;
}

export function getBillingSchedulesOutput(args: GetBillingSchedulesOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetBillingSchedulesResult> {
    return pulumi.output(args).apply(a => getBillingSchedules(a, opts))
}

/**
 * A collection of arguments for invoking getBillingSchedules.
 */
export interface GetBillingSchedulesOutputArgs {
    /**
     * The OCID of the root compartment.
     */
    compartmentId: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.OneSubsription.GetBillingSchedulesFilterArgs>[]>;
    /**
     * This param is used to get only the billing schedules for a particular Subscribed Service
     */
    subscribedServiceId?: pulumi.Input<string>;
    /**
     * This param is used to get only the billing schedules for a particular Subscription Id
     */
    subscriptionId: pulumi.Input<string>;
}