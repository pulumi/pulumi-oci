// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Compliance Record Counts in Oracle Cloud Infrastructure Fleet Apps Management service.
 *
 * Retrieve  aggregated summary information of ComplianceRecords within a Compartment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testComplianceRecordCounts = oci.FleetAppsManagement.getComplianceRecordCounts({
 *     compartmentId: compartmentId,
 *     compartmentIdInSubtree: complianceRecordCountCompartmentIdInSubtree,
 * });
 * ```
 */
export function getComplianceRecordCounts(args?: GetComplianceRecordCountsArgs, opts?: pulumi.InvokeOptions): Promise<GetComplianceRecordCountsResult> {
    args = args || {};
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:FleetAppsManagement/getComplianceRecordCounts:getComplianceRecordCounts", {
        "compartmentId": args.compartmentId,
        "compartmentIdInSubtree": args.compartmentIdInSubtree,
        "filters": args.filters,
    }, opts);
}

/**
 * A collection of arguments for invoking getComplianceRecordCounts.
 */
export interface GetComplianceRecordCountsArgs {
    /**
     * The ID of the compartment in which to list resources. Empty only if the resource OCID query param is not specified.
     */
    compartmentId?: string;
    /**
     * If set to true, resources will be returned for not only the provided compartment, but all compartments which descend from it. Which resources are returned and their field contents depends on the value of accessLevel.
     */
    compartmentIdInSubtree?: boolean;
    filters?: inputs.FleetAppsManagement.GetComplianceRecordCountsFilter[];
}

/**
 * A collection of values returned by getComplianceRecordCounts.
 */
export interface GetComplianceRecordCountsResult {
    readonly compartmentId?: string;
    readonly compartmentIdInSubtree?: boolean;
    /**
     * The list of compliance_record_aggregation_collection.
     */
    readonly complianceRecordAggregationCollections: outputs.FleetAppsManagement.GetComplianceRecordCountsComplianceRecordAggregationCollection[];
    readonly filters?: outputs.FleetAppsManagement.GetComplianceRecordCountsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
}
/**
 * This data source provides the list of Compliance Record Counts in Oracle Cloud Infrastructure Fleet Apps Management service.
 *
 * Retrieve  aggregated summary information of ComplianceRecords within a Compartment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testComplianceRecordCounts = oci.FleetAppsManagement.getComplianceRecordCounts({
 *     compartmentId: compartmentId,
 *     compartmentIdInSubtree: complianceRecordCountCompartmentIdInSubtree,
 * });
 * ```
 */
export function getComplianceRecordCountsOutput(args?: GetComplianceRecordCountsOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetComplianceRecordCountsResult> {
    args = args || {};
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:FleetAppsManagement/getComplianceRecordCounts:getComplianceRecordCounts", {
        "compartmentId": args.compartmentId,
        "compartmentIdInSubtree": args.compartmentIdInSubtree,
        "filters": args.filters,
    }, opts);
}

/**
 * A collection of arguments for invoking getComplianceRecordCounts.
 */
export interface GetComplianceRecordCountsOutputArgs {
    /**
     * The ID of the compartment in which to list resources. Empty only if the resource OCID query param is not specified.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * If set to true, resources will be returned for not only the provided compartment, but all compartments which descend from it. Which resources are returned and their field contents depends on the value of accessLevel.
     */
    compartmentIdInSubtree?: pulumi.Input<boolean>;
    filters?: pulumi.Input<pulumi.Input<inputs.FleetAppsManagement.GetComplianceRecordCountsFilterArgs>[]>;
}
