// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Subscriber resource in Oracle Cloud Infrastructure API Gateway service.
 *
 * Gets a subscriber by identifier.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testSubscriber = oci.ApiGateway.getSubscriber({
 *     subscriberId: oci_apigateway_subscriber.test_subscriber.id,
 * });
 * ```
 */
export function getSubscriber(args: GetSubscriberArgs, opts?: pulumi.InvokeOptions): Promise<GetSubscriberResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:ApiGateway/getSubscriber:getSubscriber", {
        "subscriberId": args.subscriberId,
    }, opts);
}

/**
 * A collection of arguments for invoking getSubscriber.
 */
export interface GetSubscriberArgs {
    /**
     * The ocid of the subscriber.
     */
    subscriberId: string;
}

/**
 * A collection of values returned by getSubscriber.
 */
export interface GetSubscriberResult {
    /**
     * The clients belonging to this subscriber.
     */
    readonly clients: outputs.ApiGateway.GetSubscriberClient[];
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the resource is created.
     */
    readonly compartmentId: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    readonly definedTags: {[key: string]: any};
    /**
     * A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My new resource`
     */
    readonly displayName: string;
    /**
     * Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    readonly freeformTags: {[key: string]: any};
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource.
     */
    readonly id: string;
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in a Failed state.
     */
    readonly lifecycleDetails: string;
    /**
     * The current state of the subscriber.
     */
    readonly state: string;
    readonly subscriberId: string;
    /**
     * The time this resource was created. An RFC3339 formatted datetime string.
     */
    readonly timeCreated: string;
    /**
     * The time this resource was last updated. An RFC3339 formatted datetime string.
     */
    readonly timeUpdated: string;
    /**
     * An array of [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)s of usage plan resources.
     */
    readonly usagePlans: string[];
}

export function getSubscriberOutput(args: GetSubscriberOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetSubscriberResult> {
    return pulumi.output(args).apply(a => getSubscriber(a, opts))
}

/**
 * A collection of arguments for invoking getSubscriber.
 */
export interface GetSubscriberOutputArgs {
    /**
     * The ocid of the subscriber.
     */
    subscriberId: pulumi.Input<string>;
}