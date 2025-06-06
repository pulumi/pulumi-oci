// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Subscriptions in Oracle Cloud Infrastructure Onesubscription service.
 *
 * This list API returns all subscriptions for a given plan number or subscription id or buyer email
 * and provides additional parameters to include ratecard and commitment details.
 * This API expects exactly one of the above mentioned parameters as input. If more than one parameters are provided the API will throw
 * a 400 - invalid parameters exception and if no parameters are provided it will throw a 400 - missing parameter exception
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testSubscriptions = oci.OneSubsription.getSubscriptions({
 *     compartmentId: compartmentId,
 *     buyerEmail: subscriptionBuyerEmail,
 *     isCommitInfoRequired: subscriptionIsCommitInfoRequired,
 *     planNumber: subscriptionPlanNumber,
 *     subscriptionId: testSubscription.id,
 * });
 * ```
 */
export function getSubscriptions(args: GetSubscriptionsArgs, opts?: pulumi.InvokeOptions): Promise<GetSubscriptionsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:OneSubsription/getSubscriptions:getSubscriptions", {
        "buyerEmail": args.buyerEmail,
        "compartmentId": args.compartmentId,
        "filters": args.filters,
        "isCommitInfoRequired": args.isCommitInfoRequired,
        "planNumber": args.planNumber,
        "subscriptionId": args.subscriptionId,
    }, opts);
}

/**
 * A collection of arguments for invoking getSubscriptions.
 */
export interface GetSubscriptionsArgs {
    /**
     * Buyer Email Id
     */
    buyerEmail?: string;
    /**
     * The OCID of the root compartment.
     */
    compartmentId: string;
    filters?: inputs.OneSubsription.GetSubscriptionsFilter[];
    /**
     * Boolean value to decide whether commitment services will be shown
     */
    isCommitInfoRequired?: boolean;
    /**
     * The Plan Number
     */
    planNumber?: string;
    /**
     * Line level Subscription Id
     */
    subscriptionId?: string;
}

/**
 * A collection of values returned by getSubscriptions.
 */
export interface GetSubscriptionsResult {
    readonly buyerEmail?: string;
    readonly compartmentId: string;
    readonly filters?: outputs.OneSubsription.GetSubscriptionsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    readonly isCommitInfoRequired?: boolean;
    readonly planNumber?: string;
    readonly subscriptionId?: string;
    /**
     * The list of subscriptions.
     */
    readonly subscriptions: outputs.OneSubsription.GetSubscriptionsSubscription[];
}
/**
 * This data source provides the list of Subscriptions in Oracle Cloud Infrastructure Onesubscription service.
 *
 * This list API returns all subscriptions for a given plan number or subscription id or buyer email
 * and provides additional parameters to include ratecard and commitment details.
 * This API expects exactly one of the above mentioned parameters as input. If more than one parameters are provided the API will throw
 * a 400 - invalid parameters exception and if no parameters are provided it will throw a 400 - missing parameter exception
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testSubscriptions = oci.OneSubsription.getSubscriptions({
 *     compartmentId: compartmentId,
 *     buyerEmail: subscriptionBuyerEmail,
 *     isCommitInfoRequired: subscriptionIsCommitInfoRequired,
 *     planNumber: subscriptionPlanNumber,
 *     subscriptionId: testSubscription.id,
 * });
 * ```
 */
export function getSubscriptionsOutput(args: GetSubscriptionsOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetSubscriptionsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:OneSubsription/getSubscriptions:getSubscriptions", {
        "buyerEmail": args.buyerEmail,
        "compartmentId": args.compartmentId,
        "filters": args.filters,
        "isCommitInfoRequired": args.isCommitInfoRequired,
        "planNumber": args.planNumber,
        "subscriptionId": args.subscriptionId,
    }, opts);
}

/**
 * A collection of arguments for invoking getSubscriptions.
 */
export interface GetSubscriptionsOutputArgs {
    /**
     * Buyer Email Id
     */
    buyerEmail?: pulumi.Input<string>;
    /**
     * The OCID of the root compartment.
     */
    compartmentId: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.OneSubsription.GetSubscriptionsFilterArgs>[]>;
    /**
     * Boolean value to decide whether commitment services will be shown
     */
    isCommitInfoRequired?: pulumi.Input<boolean>;
    /**
     * The Plan Number
     */
    planNumber?: pulumi.Input<string>;
    /**
     * Line level Subscription Id
     */
    subscriptionId?: pulumi.Input<string>;
}
