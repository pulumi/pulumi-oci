// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Subscriptions in Oracle Cloud Infrastructure Tenantmanagercontrolplane service.
 *
 * List the subscriptions that a compartment owns. Only the root compartment is allowed.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testSubscriptions = oci.Tenantmanagercontrolplane.getSubscriptions({
 *     compartmentId: compartmentId,
 *     entityVersion: subscriptionEntityVersion,
 *     subscriptionId: testSubscription.id,
 * });
 * ```
 */
export function getSubscriptions(args?: GetSubscriptionsArgs, opts?: pulumi.InvokeOptions): Promise<GetSubscriptionsResult> {
    args = args || {};
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Tenantmanagercontrolplane/getSubscriptions:getSubscriptions", {
        "compartmentId": args.compartmentId,
        "entityVersion": args.entityVersion,
        "filters": args.filters,
        "subscriptionId": args.subscriptionId,
    }, opts);
}

/**
 * A collection of arguments for invoking getSubscriptions.
 */
export interface GetSubscriptionsArgs {
    /**
     * The ID of the compartment in which to list resources.
     */
    compartmentId?: string;
    /**
     * The version of the subscription entity.
     */
    entityVersion?: string;
    filters?: inputs.Tenantmanagercontrolplane.GetSubscriptionsFilter[];
    /**
     * The ID of the subscription to which the tenancy is associated.
     */
    subscriptionId?: string;
}

/**
 * A collection of values returned by getSubscriptions.
 */
export interface GetSubscriptionsResult {
    /**
     * The Oracle ID ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of the owning compartment. Always a tenancy OCID.
     */
    readonly compartmentId?: string;
    /**
     * The entity version of the subscription, whether V1 (the legacy schema version), or V2 (the latest 20230401 API version).
     */
    readonly entityVersion?: string;
    readonly filters?: outputs.Tenantmanagercontrolplane.GetSubscriptionsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The list of subscription_collection.
     */
    readonly subscriptionCollections: outputs.Tenantmanagercontrolplane.GetSubscriptionsSubscriptionCollection[];
    readonly subscriptionId?: string;
}
/**
 * This data source provides the list of Subscriptions in Oracle Cloud Infrastructure Tenantmanagercontrolplane service.
 *
 * List the subscriptions that a compartment owns. Only the root compartment is allowed.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testSubscriptions = oci.Tenantmanagercontrolplane.getSubscriptions({
 *     compartmentId: compartmentId,
 *     entityVersion: subscriptionEntityVersion,
 *     subscriptionId: testSubscription.id,
 * });
 * ```
 */
export function getSubscriptionsOutput(args?: GetSubscriptionsOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetSubscriptionsResult> {
    args = args || {};
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Tenantmanagercontrolplane/getSubscriptions:getSubscriptions", {
        "compartmentId": args.compartmentId,
        "entityVersion": args.entityVersion,
        "filters": args.filters,
        "subscriptionId": args.subscriptionId,
    }, opts);
}

/**
 * A collection of arguments for invoking getSubscriptions.
 */
export interface GetSubscriptionsOutputArgs {
    /**
     * The ID of the compartment in which to list resources.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * The version of the subscription entity.
     */
    entityVersion?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.Tenantmanagercontrolplane.GetSubscriptionsFilterArgs>[]>;
    /**
     * The ID of the subscription to which the tenancy is associated.
     */
    subscriptionId?: pulumi.Input<string>;
}
