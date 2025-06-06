// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Db Node Console Histories in Oracle Cloud Infrastructure Database service.
 *
 * Lists the console histories for the specified database node.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDbNodeConsoleHistories = oci.Database.getDbNodeConsoleHistories({
 *     dbNodeId: testDbNode.id,
 *     displayName: dbNodeConsoleHistoryDisplayName,
 *     state: dbNodeConsoleHistoryState,
 * });
 * ```
 */
export function getDbNodeConsoleHistories(args: GetDbNodeConsoleHistoriesArgs, opts?: pulumi.InvokeOptions): Promise<GetDbNodeConsoleHistoriesResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Database/getDbNodeConsoleHistories:getDbNodeConsoleHistories", {
        "dbNodeId": args.dbNodeId,
        "displayName": args.displayName,
        "filters": args.filters,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getDbNodeConsoleHistories.
 */
export interface GetDbNodeConsoleHistoriesArgs {
    /**
     * The database node [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    dbNodeId: string;
    /**
     * A filter to return only resources that match the entire display name given. The match is not case sensitive.
     */
    displayName?: string;
    filters?: inputs.Database.GetDbNodeConsoleHistoriesFilter[];
    /**
     * A filter to return only resources that match the given lifecycle state exactly.
     */
    state?: string;
}

/**
 * A collection of values returned by getDbNodeConsoleHistories.
 */
export interface GetDbNodeConsoleHistoriesResult {
    /**
     * The list of console_history_collection.
     */
    readonly consoleHistoryCollections: outputs.Database.GetDbNodeConsoleHistoriesConsoleHistoryCollection[];
    /**
     * The OCID of the database node.
     */
    readonly dbNodeId: string;
    /**
     * The user-friendly name for the console history. The name does not need to be unique.
     */
    readonly displayName?: string;
    readonly filters?: outputs.Database.GetDbNodeConsoleHistoriesFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The current state of the console history.
     */
    readonly state?: string;
}
/**
 * This data source provides the list of Db Node Console Histories in Oracle Cloud Infrastructure Database service.
 *
 * Lists the console histories for the specified database node.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDbNodeConsoleHistories = oci.Database.getDbNodeConsoleHistories({
 *     dbNodeId: testDbNode.id,
 *     displayName: dbNodeConsoleHistoryDisplayName,
 *     state: dbNodeConsoleHistoryState,
 * });
 * ```
 */
export function getDbNodeConsoleHistoriesOutput(args: GetDbNodeConsoleHistoriesOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetDbNodeConsoleHistoriesResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Database/getDbNodeConsoleHistories:getDbNodeConsoleHistories", {
        "dbNodeId": args.dbNodeId,
        "displayName": args.displayName,
        "filters": args.filters,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getDbNodeConsoleHistories.
 */
export interface GetDbNodeConsoleHistoriesOutputArgs {
    /**
     * The database node [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    dbNodeId: pulumi.Input<string>;
    /**
     * A filter to return only resources that match the entire display name given. The match is not case sensitive.
     */
    displayName?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.Database.GetDbNodeConsoleHistoriesFilterArgs>[]>;
    /**
     * A filter to return only resources that match the given lifecycle state exactly.
     */
    state?: pulumi.Input<string>;
}
