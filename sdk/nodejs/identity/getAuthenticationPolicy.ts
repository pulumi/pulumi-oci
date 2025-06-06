// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Authentication Policy resource in Oracle Cloud Infrastructure Identity service.
 *
 * Gets the authentication policy for the given tenancy. You must specify your tenant’s OCID as the value for
 * the compartment ID (remember that the tenancy is simply the root compartment).
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testAuthenticationPolicy = oci.Identity.getAuthenticationPolicy({
 *     compartmentId: tenancyOcid,
 * });
 * ```
 */
export function getAuthenticationPolicy(args: GetAuthenticationPolicyArgs, opts?: pulumi.InvokeOptions): Promise<GetAuthenticationPolicyResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Identity/getAuthenticationPolicy:getAuthenticationPolicy", {
        "compartmentId": args.compartmentId,
    }, opts);
}

/**
 * A collection of arguments for invoking getAuthenticationPolicy.
 */
export interface GetAuthenticationPolicyArgs {
    /**
     * The OCID of the compartment.
     */
    compartmentId: string;
}

/**
 * A collection of values returned by getAuthenticationPolicy.
 */
export interface GetAuthenticationPolicyResult {
    /**
     * Compartment OCID.
     */
    readonly compartmentId: string;
    readonly id: string;
    /**
     * Network policy, Consists of a list of Network Source ids.
     */
    readonly networkPolicies: outputs.Identity.GetAuthenticationPolicyNetworkPolicy[];
    /**
     * Password policy, currently set for the given compartment.
     */
    readonly passwordPolicies: outputs.Identity.GetAuthenticationPolicyPasswordPolicy[];
}
/**
 * This data source provides details about a specific Authentication Policy resource in Oracle Cloud Infrastructure Identity service.
 *
 * Gets the authentication policy for the given tenancy. You must specify your tenant’s OCID as the value for
 * the compartment ID (remember that the tenancy is simply the root compartment).
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testAuthenticationPolicy = oci.Identity.getAuthenticationPolicy({
 *     compartmentId: tenancyOcid,
 * });
 * ```
 */
export function getAuthenticationPolicyOutput(args: GetAuthenticationPolicyOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetAuthenticationPolicyResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Identity/getAuthenticationPolicy:getAuthenticationPolicy", {
        "compartmentId": args.compartmentId,
    }, opts);
}

/**
 * A collection of arguments for invoking getAuthenticationPolicy.
 */
export interface GetAuthenticationPolicyOutputArgs {
    /**
     * The OCID of the compartment.
     */
    compartmentId: pulumi.Input<string>;
}
