// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Billing Schedules in Oracle Cloud Infrastructure Osub Billing Schedule service.
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
 * const testBillingSchedules = oci.OsubBillingSchedule.getBillingSchedule({
 *     compartmentId: _var.compartment_id,
 *     subscriptionId: oci_ons_subscription.test_subscription.id,
 *     subscribedServiceId: oci_core_service.test_service.id,
 *     xOneOriginRegion: _var.billing_schedule_x_one_origin_region,
 * });
 * ```
 */
export function getBillingSchedule(args: GetBillingScheduleArgs, opts?: pulumi.InvokeOptions): Promise<GetBillingScheduleResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:OsubBillingSchedule/getBillingSchedule:getBillingSchedule", {
        "compartmentId": args.compartmentId,
        "filters": args.filters,
        "subscribedServiceId": args.subscribedServiceId,
        "subscriptionId": args.subscriptionId,
        "xOneOriginRegion": args.xOneOriginRegion,
    }, opts);
}

/**
 * A collection of arguments for invoking getBillingSchedule.
 */
export interface GetBillingScheduleArgs {
    /**
     * The OCID of the compartment.
     */
    compartmentId: string;
    filters?: inputs.OsubBillingSchedule.GetBillingScheduleFilter[];
    /**
     * This param is used to get only the billing schedules for a particular Subscribed Service
     */
    subscribedServiceId?: string;
    /**
     * This param is used to get only the billing schedules for a particular Subscription Id
     */
    subscriptionId: string;
    /**
     * The Oracle Cloud Infrastructure home region name in case home region is not us-ashburn-1 (IAD), e.g. ap-mumbai-1, us-phoenix-1 etc.
     */
    xOneOriginRegion?: string;
}

/**
 * A collection of values returned by getBillingSchedule.
 */
export interface GetBillingScheduleResult {
    /**
     * The list of billing_schedules.
     */
    readonly billingSchedules: outputs.OsubBillingSchedule.GetBillingScheduleBillingSchedule[];
    readonly compartmentId: string;
    readonly filters?: outputs.OsubBillingSchedule.GetBillingScheduleFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    readonly subscribedServiceId?: string;
    readonly subscriptionId: string;
    readonly xOneOriginRegion?: string;
}

export function getBillingScheduleOutput(args: GetBillingScheduleOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetBillingScheduleResult> {
    return pulumi.output(args).apply(a => getBillingSchedule(a, opts))
}

/**
 * A collection of arguments for invoking getBillingSchedule.
 */
export interface GetBillingScheduleOutputArgs {
    /**
     * The OCID of the compartment.
     */
    compartmentId: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.OsubBillingSchedule.GetBillingScheduleFilterArgs>[]>;
    /**
     * This param is used to get only the billing schedules for a particular Subscribed Service
     */
    subscribedServiceId?: pulumi.Input<string>;
    /**
     * This param is used to get only the billing schedules for a particular Subscription Id
     */
    subscriptionId: pulumi.Input<string>;
    /**
     * The Oracle Cloud Infrastructure home region name in case home region is not us-ashburn-1 (IAD), e.g. ap-mumbai-1, us-phoenix-1 etc.
     */
    xOneOriginRegion?: pulumi.Input<string>;
}