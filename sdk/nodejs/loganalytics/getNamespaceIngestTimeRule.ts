// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Namespace Ingest Time Rule resource in Oracle Cloud Infrastructure Log Analytics service.
 *
 * Gets detailed information about the specified ingest time rule such as description, defined tags, and free-form tags.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testNamespaceIngestTimeRule = oci.LogAnalytics.getNamespaceIngestTimeRule({
 *     ingestTimeRuleId: oci_events_rule.test_rule.id,
 *     namespace: _var.namespace_ingest_time_rule_namespace,
 * });
 * ```
 */
export function getNamespaceIngestTimeRule(args: GetNamespaceIngestTimeRuleArgs, opts?: pulumi.InvokeOptions): Promise<GetNamespaceIngestTimeRuleResult> {

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:LogAnalytics/getNamespaceIngestTimeRule:getNamespaceIngestTimeRule", {
        "ingestTimeRuleId": args.ingestTimeRuleId,
        "namespace": args.namespace,
    }, opts);
}

/**
 * A collection of arguments for invoking getNamespaceIngestTimeRule.
 */
export interface GetNamespaceIngestTimeRuleArgs {
    /**
     * Unique ocid of the ingest time rule.
     */
    ingestTimeRuleId: string;
    /**
     * The Logging Analytics namespace used for the request.
     */
    namespace: string;
}

/**
 * A collection of values returned by getNamespaceIngestTimeRule.
 */
export interface GetNamespaceIngestTimeRuleResult {
    /**
     * The action(s) to be performed if the ingest time rule condition(s) are satisfied.
     */
    readonly actions: outputs.LogAnalytics.GetNamespaceIngestTimeRuleAction[];
    /**
     * Compartment Identifier [OCID] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    readonly compartmentId: string;
    /**
     * The condition(s) to evaluate for an ingest time rule.
     */
    readonly conditions: outputs.LogAnalytics.GetNamespaceIngestTimeRuleCondition[];
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    readonly definedTags: {[key: string]: any};
    /**
     * Description for this resource.
     */
    readonly description: string;
    /**
     * The ingest time rule display name.
     */
    readonly displayName: string;
    /**
     * Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    readonly freeformTags: {[key: string]: any};
    /**
     * The log analytics entity OCID. This ID is a reference used by log analytics features and it represents a resource that is provisioned and managed by the customer on their premises or on the cloud.
     */
    readonly id: string;
    readonly ingestTimeRuleId: string;
    /**
     * A flag indicating whether or not the ingest time rule is enabled.
     */
    readonly isEnabled: boolean;
    /**
     * The namespace of the extracted metric. A valid value starts with an alphabetical character and includes only alphanumeric characters and underscores (_).
     */
    readonly namespace: string;
    /**
     * The current state of the ingest time rule.
     */
    readonly state: string;
    /**
     * The date and time the resource was created, in the format defined by RFC3339.
     */
    readonly timeCreated: string;
    /**
     * The date and time the resource was last updated, in the format defined by RFC3339.
     */
    readonly timeUpdated: string;
}
/**
 * This data source provides details about a specific Namespace Ingest Time Rule resource in Oracle Cloud Infrastructure Log Analytics service.
 *
 * Gets detailed information about the specified ingest time rule such as description, defined tags, and free-form tags.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testNamespaceIngestTimeRule = oci.LogAnalytics.getNamespaceIngestTimeRule({
 *     ingestTimeRuleId: oci_events_rule.test_rule.id,
 *     namespace: _var.namespace_ingest_time_rule_namespace,
 * });
 * ```
 */
export function getNamespaceIngestTimeRuleOutput(args: GetNamespaceIngestTimeRuleOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetNamespaceIngestTimeRuleResult> {
    return pulumi.output(args).apply((a: any) => getNamespaceIngestTimeRule(a, opts))
}

/**
 * A collection of arguments for invoking getNamespaceIngestTimeRule.
 */
export interface GetNamespaceIngestTimeRuleOutputArgs {
    /**
     * Unique ocid of the ingest time rule.
     */
    ingestTimeRuleId: pulumi.Input<string>;
    /**
     * The Logging Analytics namespace used for the request.
     */
    namespace: pulumi.Input<string>;
}