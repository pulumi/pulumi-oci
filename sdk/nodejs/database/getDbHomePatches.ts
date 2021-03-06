// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Db Home Patches in Oracle Cloud Infrastructure Database service.
 *
 * Lists patches applicable to the requested Database Home.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDbHomePatches = oci.Database.getDbHomePatches({
 *     dbHomeId: oci_database_db_home.test_db_home.id,
 * });
 * ```
 */
export function getDbHomePatches(args: GetDbHomePatchesArgs, opts?: pulumi.InvokeOptions): Promise<GetDbHomePatchesResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:Database/getDbHomePatches:getDbHomePatches", {
        "dbHomeId": args.dbHomeId,
        "filters": args.filters,
    }, opts);
}

/**
 * A collection of arguments for invoking getDbHomePatches.
 */
export interface GetDbHomePatchesArgs {
    /**
     * The Database Home [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    dbHomeId: string;
    filters?: inputs.Database.GetDbHomePatchesFilter[];
}

/**
 * A collection of values returned by getDbHomePatches.
 */
export interface GetDbHomePatchesResult {
    readonly dbHomeId: string;
    readonly filters?: outputs.Database.GetDbHomePatchesFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The list of patches.
     */
    readonly patches: outputs.Database.GetDbHomePatchesPatch[];
}

export function getDbHomePatchesOutput(args: GetDbHomePatchesOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetDbHomePatchesResult> {
    return pulumi.output(args).apply(a => getDbHomePatches(a, opts))
}

/**
 * A collection of arguments for invoking getDbHomePatches.
 */
export interface GetDbHomePatchesOutputArgs {
    /**
     * The Database Home [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    dbHomeId: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.Database.GetDbHomePatchesFilterArgs>[]>;
}
