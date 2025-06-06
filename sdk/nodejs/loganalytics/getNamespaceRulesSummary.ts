// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Namespace Rules Summary resource in Oracle Cloud Infrastructure Log Analytics service.
 *
 * Returns the count of detection rules in a compartment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testNamespaceRulesSummary = oci.LogAnalytics.getNamespaceRulesSummary({
 *     compartmentId: compartmentId,
 *     namespace: namespaceRulesSummaryNamespace,
 * });
 * ```
 */
export function getNamespaceRulesSummary(args: GetNamespaceRulesSummaryArgs, opts?: pulumi.InvokeOptions): Promise<GetNamespaceRulesSummaryResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:LogAnalytics/getNamespaceRulesSummary:getNamespaceRulesSummary", {
        "compartmentId": args.compartmentId,
        "namespace": args.namespace,
    }, opts);
}

/**
 * A collection of arguments for invoking getNamespaceRulesSummary.
 */
export interface GetNamespaceRulesSummaryArgs {
    /**
     * The ID of the compartment in which to list resources.
     */
    compartmentId: string;
    /**
     * The Logging Analytics namespace used for the request.
     */
    namespace: string;
}

/**
 * A collection of values returned by getNamespaceRulesSummary.
 */
export interface GetNamespaceRulesSummaryResult {
    readonly compartmentId: string;
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The count of ingest time rules.
     */
    readonly ingestTimeRulesCount: number;
    readonly namespace: string;
    /**
     * The count of saved search rules.
     */
    readonly savedSearchRulesCount: number;
    /**
     * The total count of detection rules.
     */
    readonly totalCount: number;
}
/**
 * This data source provides details about a specific Namespace Rules Summary resource in Oracle Cloud Infrastructure Log Analytics service.
 *
 * Returns the count of detection rules in a compartment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testNamespaceRulesSummary = oci.LogAnalytics.getNamespaceRulesSummary({
 *     compartmentId: compartmentId,
 *     namespace: namespaceRulesSummaryNamespace,
 * });
 * ```
 */
export function getNamespaceRulesSummaryOutput(args: GetNamespaceRulesSummaryOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetNamespaceRulesSummaryResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:LogAnalytics/getNamespaceRulesSummary:getNamespaceRulesSummary", {
        "compartmentId": args.compartmentId,
        "namespace": args.namespace,
    }, opts);
}

/**
 * A collection of arguments for invoking getNamespaceRulesSummary.
 */
export interface GetNamespaceRulesSummaryOutputArgs {
    /**
     * The ID of the compartment in which to list resources.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * The Logging Analytics namespace used for the request.
     */
    namespace: pulumi.Input<string>;
}
