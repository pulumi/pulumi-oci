// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Migration Object Types in Oracle Cloud Infrastructure Database Migration service.
 *
 * Display sample object types to exclude or include for a Migration.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testMigrationObjectTypes = pulumi.output(oci.DatabaseMigration.getMigrationObjectTypes());
 * ```
 */
export function getMigrationObjectTypes(args?: GetMigrationObjectTypesArgs, opts?: pulumi.InvokeOptions): Promise<GetMigrationObjectTypesResult> {
    args = args || {};
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:DatabaseMigration/getMigrationObjectTypes:getMigrationObjectTypes", {
        "filters": args.filters,
    }, opts);
}

/**
 * A collection of arguments for invoking getMigrationObjectTypes.
 */
export interface GetMigrationObjectTypesArgs {
    filters?: inputs.DatabaseMigration.GetMigrationObjectTypesFilter[];
}

/**
 * A collection of values returned by getMigrationObjectTypes.
 */
export interface GetMigrationObjectTypesResult {
    readonly filters?: outputs.DatabaseMigration.GetMigrationObjectTypesFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The list of migration_object_type_summary_collection.
     */
    readonly migrationObjectTypeSummaryCollections: outputs.DatabaseMigration.GetMigrationObjectTypesMigrationObjectTypeSummaryCollection[];
}

export function getMigrationObjectTypesOutput(args?: GetMigrationObjectTypesOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetMigrationObjectTypesResult> {
    return pulumi.output(args).apply(a => getMigrationObjectTypes(a, opts))
}

/**
 * A collection of arguments for invoking getMigrationObjectTypes.
 */
export interface GetMigrationObjectTypesOutputArgs {
    filters?: pulumi.Input<pulumi.Input<inputs.DatabaseMigration.GetMigrationObjectTypesFilterArgs>[]>;
}