// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Namespace Ingest Time Rules in Oracle Cloud Infrastructure Log Analytics service.
 *
 * Returns a list of ingest time rules in a compartment. You may limit the number of rules, provide sorting options, and filter the results.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testNamespaceIngestTimeRules = oci.LogAnalytics.getNamespaceIngestTimeRules({
 *     compartmentId: compartmentId,
 *     namespace: namespaceIngestTimeRuleNamespace,
 *     conditionKind: namespaceIngestTimeRuleConditionKind,
 *     displayName: namespaceIngestTimeRuleDisplayName,
 *     fieldName: namespaceIngestTimeRuleFieldName,
 *     fieldValue: namespaceIngestTimeRuleFieldValue,
 *     state: namespaceIngestTimeRuleState,
 * });
 * ```
 */
export function getNamespaceIngestTimeRules(args: GetNamespaceIngestTimeRulesArgs, opts?: pulumi.InvokeOptions): Promise<GetNamespaceIngestTimeRulesResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:LogAnalytics/getNamespaceIngestTimeRules:getNamespaceIngestTimeRules", {
        "compartmentId": args.compartmentId,
        "conditionKind": args.conditionKind,
        "displayName": args.displayName,
        "fieldName": args.fieldName,
        "fieldValue": args.fieldValue,
        "filters": args.filters,
        "namespace": args.namespace,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getNamespaceIngestTimeRules.
 */
export interface GetNamespaceIngestTimeRulesArgs {
    /**
     * The ID of the compartment in which to list resources.
     */
    compartmentId: string;
    /**
     * The ingest time rule condition kind used for filtering. Only rules with conditions of the specified kind will be returned.
     */
    conditionKind?: string;
    /**
     * A filter to return rules whose displayName matches in whole or in part the specified value. The match is case-insensitive.
     */
    displayName?: string;
    /**
     * The field name used for filtering. Only rules using the specified field name will be returned.
     */
    fieldName?: string;
    /**
     * The field value used for filtering. Only rules using the specified field value will be returned.
     */
    fieldValue?: string;
    filters?: inputs.LogAnalytics.GetNamespaceIngestTimeRulesFilter[];
    /**
     * The Logging Analytics namespace used for the request.
     */
    namespace: string;
    /**
     * The rule lifecycle state used for filtering. Currently supported values are ACTIVE and DELETED.
     */
    state?: string;
}

/**
 * A collection of values returned by getNamespaceIngestTimeRules.
 */
export interface GetNamespaceIngestTimeRulesResult {
    /**
     * Compartment Identifier [OCID] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    readonly compartmentId: string;
    readonly conditionKind?: string;
    /**
     * The ingest time rule display name.
     */
    readonly displayName?: string;
    /**
     * The field name to be evaluated.
     */
    readonly fieldName?: string;
    /**
     * The field value to be evaluated.
     */
    readonly fieldValue?: string;
    readonly filters?: outputs.LogAnalytics.GetNamespaceIngestTimeRulesFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The list of ingest_time_rule_summary_collection.
     */
    readonly ingestTimeRuleSummaryCollections: outputs.LogAnalytics.GetNamespaceIngestTimeRulesIngestTimeRuleSummaryCollection[];
    /**
     * The namespace of the extracted metric. A valid value starts with an alphabetical character and includes only alphanumeric characters and underscores (_).
     */
    readonly namespace: string;
    /**
     * The current state of the ingest time rule.
     */
    readonly state?: string;
}
/**
 * This data source provides the list of Namespace Ingest Time Rules in Oracle Cloud Infrastructure Log Analytics service.
 *
 * Returns a list of ingest time rules in a compartment. You may limit the number of rules, provide sorting options, and filter the results.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testNamespaceIngestTimeRules = oci.LogAnalytics.getNamespaceIngestTimeRules({
 *     compartmentId: compartmentId,
 *     namespace: namespaceIngestTimeRuleNamespace,
 *     conditionKind: namespaceIngestTimeRuleConditionKind,
 *     displayName: namespaceIngestTimeRuleDisplayName,
 *     fieldName: namespaceIngestTimeRuleFieldName,
 *     fieldValue: namespaceIngestTimeRuleFieldValue,
 *     state: namespaceIngestTimeRuleState,
 * });
 * ```
 */
export function getNamespaceIngestTimeRulesOutput(args: GetNamespaceIngestTimeRulesOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetNamespaceIngestTimeRulesResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:LogAnalytics/getNamespaceIngestTimeRules:getNamespaceIngestTimeRules", {
        "compartmentId": args.compartmentId,
        "conditionKind": args.conditionKind,
        "displayName": args.displayName,
        "fieldName": args.fieldName,
        "fieldValue": args.fieldValue,
        "filters": args.filters,
        "namespace": args.namespace,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getNamespaceIngestTimeRules.
 */
export interface GetNamespaceIngestTimeRulesOutputArgs {
    /**
     * The ID of the compartment in which to list resources.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * The ingest time rule condition kind used for filtering. Only rules with conditions of the specified kind will be returned.
     */
    conditionKind?: pulumi.Input<string>;
    /**
     * A filter to return rules whose displayName matches in whole or in part the specified value. The match is case-insensitive.
     */
    displayName?: pulumi.Input<string>;
    /**
     * The field name used for filtering. Only rules using the specified field name will be returned.
     */
    fieldName?: pulumi.Input<string>;
    /**
     * The field value used for filtering. Only rules using the specified field value will be returned.
     */
    fieldValue?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.LogAnalytics.GetNamespaceIngestTimeRulesFilterArgs>[]>;
    /**
     * The Logging Analytics namespace used for the request.
     */
    namespace: pulumi.Input<string>;
    /**
     * The rule lifecycle state used for filtering. Currently supported values are ACTIVE and DELETED.
     */
    state?: pulumi.Input<string>;
}
