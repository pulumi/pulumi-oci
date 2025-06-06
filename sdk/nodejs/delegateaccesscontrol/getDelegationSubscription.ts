// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Delegation Subscription resource in Oracle Cloud Infrastructure Delegate Access Control service.
 *
 * Gets a DelegationSubscription by identifier
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDelegationSubscription = oci.DelegateAccessControl.getDelegationSubscription({
 *     delegationSubscriptionId: testDelegationSubscriptionOciDelegateAccessControlDelegationSubscription.id,
 * });
 * ```
 */
export function getDelegationSubscription(args: GetDelegationSubscriptionArgs, opts?: pulumi.InvokeOptions): Promise<GetDelegationSubscriptionResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:DelegateAccessControl/getDelegationSubscription:getDelegationSubscription", {
        "delegationSubscriptionId": args.delegationSubscriptionId,
    }, opts);
}

/**
 * A collection of arguments for invoking getDelegationSubscription.
 */
export interface GetDelegationSubscriptionArgs {
    /**
     * unique Delegation Subscription identifier
     */
    delegationSubscriptionId: string;
}

/**
 * A collection of values returned by getDelegationSubscription.
 */
export interface GetDelegationSubscriptionResult {
    /**
     * The OCID of the compartment that contains the Delegation Subscription.
     */
    readonly compartmentId: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    readonly definedTags: {[key: string]: string};
    readonly delegationSubscriptionId: string;
    /**
     * Description of the Delegation Subscription.
     */
    readonly description: string;
    /**
     * Display name
     */
    readonly displayName: string;
    /**
     * Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    readonly freeformTags: {[key: string]: string};
    /**
     * Unique identifier for the Delegation Subscription.
     */
    readonly id: string;
    /**
     * Description of the current lifecycle state in more detail.
     */
    readonly lifecycleStateDetails: string;
    /**
     * Unique identifier of the Service Provider.
     */
    readonly serviceProviderId: string;
    /**
     * The current lifecycle state of the Service Provider.
     */
    readonly state: string;
    /**
     * Subscribed Service Provider Service Type.
     */
    readonly subscribedServiceType: string;
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    readonly systemTags: {[key: string]: string};
    /**
     * Time when the Service Provider was created expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format, e.g. '2020-05-22T21:10:29.600Z'
     */
    readonly timeCreated: string;
    /**
     * Time when the Service Provider was last modified expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format, e.g. '2020-05-22T21:10:29.600Z'
     */
    readonly timeUpdated: string;
}
/**
 * This data source provides details about a specific Delegation Subscription resource in Oracle Cloud Infrastructure Delegate Access Control service.
 *
 * Gets a DelegationSubscription by identifier
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDelegationSubscription = oci.DelegateAccessControl.getDelegationSubscription({
 *     delegationSubscriptionId: testDelegationSubscriptionOciDelegateAccessControlDelegationSubscription.id,
 * });
 * ```
 */
export function getDelegationSubscriptionOutput(args: GetDelegationSubscriptionOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetDelegationSubscriptionResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:DelegateAccessControl/getDelegationSubscription:getDelegationSubscription", {
        "delegationSubscriptionId": args.delegationSubscriptionId,
    }, opts);
}

/**
 * A collection of arguments for invoking getDelegationSubscription.
 */
export interface GetDelegationSubscriptionOutputArgs {
    /**
     * unique Delegation Subscription identifier
     */
    delegationSubscriptionId: pulumi.Input<string>;
}
