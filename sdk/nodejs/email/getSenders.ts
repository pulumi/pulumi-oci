// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Senders in Oracle Cloud Infrastructure Email service.
 *
 * Gets a collection of approved sender email addresses and sender IDs.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testSenders = oci.Email.getSenders({
 *     compartmentId: _var.compartment_id,
 *     domain: _var.sender_domain,
 *     emailAddress: _var.sender_email_address,
 *     state: _var.sender_state,
 * });
 * ```
 */
export function getSenders(args: GetSendersArgs, opts?: pulumi.InvokeOptions): Promise<GetSendersResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:Email/getSenders:getSenders", {
        "compartmentId": args.compartmentId,
        "domain": args.domain,
        "emailAddress": args.emailAddress,
        "filters": args.filters,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getSenders.
 */
export interface GetSendersArgs {
    /**
     * The OCID for the compartment.
     */
    compartmentId: string;
    /**
     * A filter to only return resources that match the given domain exactly.
     */
    domain?: string;
    /**
     * The email address of the approved sender.
     */
    emailAddress?: string;
    filters?: inputs.Email.GetSendersFilter[];
    /**
     * The current state of a sender.
     */
    state?: string;
}

/**
 * A collection of values returned by getSenders.
 */
export interface GetSendersResult {
    /**
     * The OCID for the compartment.
     */
    readonly compartmentId: string;
    readonly domain?: string;
    /**
     * The email address of the sender.
     */
    readonly emailAddress?: string;
    readonly filters?: outputs.Email.GetSendersFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The list of senders.
     */
    readonly senders: outputs.Email.GetSendersSender[];
    /**
     * The current status of the approved sender.
     */
    readonly state?: string;
}

export function getSendersOutput(args: GetSendersOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetSendersResult> {
    return pulumi.output(args).apply(a => getSenders(a, opts))
}

/**
 * A collection of arguments for invoking getSenders.
 */
export interface GetSendersOutputArgs {
    /**
     * The OCID for the compartment.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * A filter to only return resources that match the given domain exactly.
     */
    domain?: pulumi.Input<string>;
    /**
     * The email address of the approved sender.
     */
    emailAddress?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.Email.GetSendersFilterArgs>[]>;
    /**
     * The current state of a sender.
     */
    state?: pulumi.Input<string>;
}
