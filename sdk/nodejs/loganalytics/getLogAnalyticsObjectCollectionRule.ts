// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Log Analytics Object Collection Rule resource in Oracle Cloud Infrastructure Log Analytics service.
 *
 * Gets a configured object storage based collection rule by given id
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testLogAnalyticsObjectCollectionRule = oci.LogAnalytics.getLogAnalyticsObjectCollectionRule({
 *     logAnalyticsObjectCollectionRuleId: oci_log_analytics_log_analytics_object_collection_rule.test_log_analytics_object_collection_rule.id,
 *     namespace: _var.log_analytics_object_collection_rule_namespace,
 * });
 * ```
 */
export function getLogAnalyticsObjectCollectionRule(args: GetLogAnalyticsObjectCollectionRuleArgs, opts?: pulumi.InvokeOptions): Promise<GetLogAnalyticsObjectCollectionRuleResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:LogAnalytics/getLogAnalyticsObjectCollectionRule:getLogAnalyticsObjectCollectionRule", {
        "logAnalyticsObjectCollectionRuleId": args.logAnalyticsObjectCollectionRuleId,
        "namespace": args.namespace,
    }, opts);
}

/**
 * A collection of arguments for invoking getLogAnalyticsObjectCollectionRule.
 */
export interface GetLogAnalyticsObjectCollectionRuleArgs {
    /**
     * The Logging Analytics Object Collection Rule [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)
     */
    logAnalyticsObjectCollectionRuleId: string;
    /**
     * The Logging Analytics namespace used for the request.
     */
    namespace: string;
}

/**
 * A collection of values returned by getLogAnalyticsObjectCollectionRule.
 */
export interface GetLogAnalyticsObjectCollectionRuleResult {
    /**
     * An optional character encoding to aid in detecting the character encoding of the contents of the objects while processing. It is recommended to set this value as ISO_8589_1 when configuring content of the objects having more numeric characters, and very few alphabets. For e.g. this applies when configuring VCN Flow Logs.
     */
    readonly charEncoding: string;
    /**
     * The type of collection. Supported collection types: LIVE, HISTORIC, HISTORIC_LIVE
     */
    readonly collectionType: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to which this rule belongs.
     */
    readonly compartmentId: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    readonly definedTags: {[key: string]: any};
    /**
     * A string that describes the details of the rule. It does not have to be unique, and can be changed. Avoid entering confidential information.
     */
    readonly description: string;
    /**
     * Logging Analytics entity OCID to associate the processed logs with.
     */
    readonly entityId: string;
    /**
     * Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    readonly freeformTags: {[key: string]: any};
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this rule.
     */
    readonly id: string;
    /**
     * A detailed status of the life cycle state.
     */
    readonly lifecycleDetails: string;
    readonly logAnalyticsObjectCollectionRuleId: string;
    /**
     * Logging Analytics Log group OCID to associate the processed logs with.
     */
    readonly logGroupId: string;
    /**
     * Name of the Logging Analytics Source to use for the processing.
     */
    readonly logSourceName: string;
    /**
     * A unique name to the rule. The name must be unique, within the tenancy, and cannot be changed.
     */
    readonly name: string;
    readonly namespace: string;
    /**
     * When the filters are provided, only the objects matching the filters are picked up for processing. The matchType supported is exact match and accommodates wildcard "*". For more information on filters, see [Event Filters](https://docs.oracle.com/en-us/iaas/Content/Events/Concepts/filterevents.htm).
     */
    readonly objectNameFilters: string[];
    /**
     * Name of the Object Storage bucket.
     */
    readonly osBucketName: string;
    /**
     * Object Storage namespace.
     */
    readonly osNamespace: string;
    /**
     * Use this to override some property values which are defined at bucket level to the scope of object. Supported propeties for override are, logSourceName, charEncoding. Supported matchType for override are "contains".
     */
    readonly overrides: outputs.LogAnalytics.GetLogAnalyticsObjectCollectionRuleOverride[];
    /**
     * The oldest time of the file in the bucket to consider for collection. Accepted values are: BEGINNING or CURRENT_TIME or RFC3339 formatted datetime string. When collectionType is LIVE, specifying pollSince value other than CURRENT_TIME will result in error.
     */
    readonly pollSince: string;
    /**
     * The oldest time of the file in the bucket to consider for collection. Accepted values are: CURRENT_TIME or RFC3339 formatted datetime string. When collectionType is LIVE, specifying pollTill will result in error.
     */
    readonly pollTill: string;
    /**
     * The current state of the rule.
     */
    readonly state: string;
    /**
     * The time when this rule was created. An RFC3339 formatted datetime string.
     */
    readonly timeCreated: string;
    /**
     * The time when this rule was last updated. An RFC3339 formatted datetime string.
     */
    readonly timeUpdated: string;
}

export function getLogAnalyticsObjectCollectionRuleOutput(args: GetLogAnalyticsObjectCollectionRuleOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetLogAnalyticsObjectCollectionRuleResult> {
    return pulumi.output(args).apply(a => getLogAnalyticsObjectCollectionRule(a, opts))
}

/**
 * A collection of arguments for invoking getLogAnalyticsObjectCollectionRule.
 */
export interface GetLogAnalyticsObjectCollectionRuleOutputArgs {
    /**
     * The Logging Analytics Object Collection Rule [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)
     */
    logAnalyticsObjectCollectionRuleId: pulumi.Input<string>;
    /**
     * The Logging Analytics namespace used for the request.
     */
    namespace: pulumi.Input<string>;
}
