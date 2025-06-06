// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Db Home Patch History Entries in Oracle Cloud Infrastructure Database service.
 *
 * Lists the history of patch operations on the specified Database Home.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDbHomePatchHistoryEntries = oci.Database.getDbHomePatchHistoryEntries({
 *     dbHomeId: testDbHome.id,
 * });
 * ```
 */
export function getDbHomePatchHistoryEntries(args: GetDbHomePatchHistoryEntriesArgs, opts?: pulumi.InvokeOptions): Promise<GetDbHomePatchHistoryEntriesResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Database/getDbHomePatchHistoryEntries:getDbHomePatchHistoryEntries", {
        "dbHomeId": args.dbHomeId,
        "filters": args.filters,
    }, opts);
}

/**
 * A collection of arguments for invoking getDbHomePatchHistoryEntries.
 */
export interface GetDbHomePatchHistoryEntriesArgs {
    /**
     * The Database Home [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    dbHomeId: string;
    filters?: inputs.Database.GetDbHomePatchHistoryEntriesFilter[];
}

/**
 * A collection of values returned by getDbHomePatchHistoryEntries.
 */
export interface GetDbHomePatchHistoryEntriesResult {
    readonly dbHomeId: string;
    readonly filters?: outputs.Database.GetDbHomePatchHistoryEntriesFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The list of patch_history_entries.
     */
    readonly patchHistoryEntries: outputs.Database.GetDbHomePatchHistoryEntriesPatchHistoryEntry[];
}
/**
 * This data source provides the list of Db Home Patch History Entries in Oracle Cloud Infrastructure Database service.
 *
 * Lists the history of patch operations on the specified Database Home.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDbHomePatchHistoryEntries = oci.Database.getDbHomePatchHistoryEntries({
 *     dbHomeId: testDbHome.id,
 * });
 * ```
 */
export function getDbHomePatchHistoryEntriesOutput(args: GetDbHomePatchHistoryEntriesOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetDbHomePatchHistoryEntriesResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Database/getDbHomePatchHistoryEntries:getDbHomePatchHistoryEntries", {
        "dbHomeId": args.dbHomeId,
        "filters": args.filters,
    }, opts);
}

/**
 * A collection of arguments for invoking getDbHomePatchHistoryEntries.
 */
export interface GetDbHomePatchHistoryEntriesOutputArgs {
    /**
     * The Database Home [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    dbHomeId: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.Database.GetDbHomePatchHistoryEntriesFilterArgs>[]>;
}
