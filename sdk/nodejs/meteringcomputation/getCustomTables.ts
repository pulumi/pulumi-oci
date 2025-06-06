// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Custom Tables in Oracle Cloud Infrastructure Metering Computation service.
 *
 * Returns the saved custom table list.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testCustomTables = oci.MeteringComputation.getCustomTables({
 *     compartmentId: compartmentId,
 *     savedReportId: testSavedReport.id,
 * });
 * ```
 */
export function getCustomTables(args: GetCustomTablesArgs, opts?: pulumi.InvokeOptions): Promise<GetCustomTablesResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:MeteringComputation/getCustomTables:getCustomTables", {
        "compartmentId": args.compartmentId,
        "filters": args.filters,
        "savedReportId": args.savedReportId,
    }, opts);
}

/**
 * A collection of arguments for invoking getCustomTables.
 */
export interface GetCustomTablesArgs {
    /**
     * The compartment ID in which to list resources.
     */
    compartmentId: string;
    filters?: inputs.MeteringComputation.GetCustomTablesFilter[];
    /**
     * The saved report ID in which to list resources.
     */
    savedReportId: string;
}

/**
 * A collection of values returned by getCustomTables.
 */
export interface GetCustomTablesResult {
    /**
     * The custom table compartment OCID.
     */
    readonly compartmentId: string;
    /**
     * The list of custom_table_collection.
     */
    readonly customTableCollections: outputs.MeteringComputation.GetCustomTablesCustomTableCollection[];
    readonly filters?: outputs.MeteringComputation.GetCustomTablesFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The custom table associated saved report OCID.
     */
    readonly savedReportId: string;
}
/**
 * This data source provides the list of Custom Tables in Oracle Cloud Infrastructure Metering Computation service.
 *
 * Returns the saved custom table list.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testCustomTables = oci.MeteringComputation.getCustomTables({
 *     compartmentId: compartmentId,
 *     savedReportId: testSavedReport.id,
 * });
 * ```
 */
export function getCustomTablesOutput(args: GetCustomTablesOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetCustomTablesResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:MeteringComputation/getCustomTables:getCustomTables", {
        "compartmentId": args.compartmentId,
        "filters": args.filters,
        "savedReportId": args.savedReportId,
    }, opts);
}

/**
 * A collection of arguments for invoking getCustomTables.
 */
export interface GetCustomTablesOutputArgs {
    /**
     * The compartment ID in which to list resources.
     */
    compartmentId: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.MeteringComputation.GetCustomTablesFilterArgs>[]>;
    /**
     * The saved report ID in which to list resources.
     */
    savedReportId: pulumi.Input<string>;
}
