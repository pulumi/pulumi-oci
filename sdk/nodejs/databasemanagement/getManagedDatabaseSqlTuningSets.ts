// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Managed Database Sql Tuning Sets in Oracle Cloud Infrastructure Database Management service.
 *
 * Lists the SQL tuning sets for the specified Managed Database.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testManagedDatabaseSqlTuningSets = oci.DatabaseManagement.getManagedDatabaseSqlTuningSets({
 *     managedDatabaseId: testManagedDatabase.id,
 *     nameContains: managedDatabaseSqlTuningSetNameContains,
 *     opcNamedCredentialId: managedDatabaseSqlTuningSetOpcNamedCredentialId,
 *     owner: managedDatabaseSqlTuningSetOwner,
 * });
 * ```
 */
export function getManagedDatabaseSqlTuningSets(args: GetManagedDatabaseSqlTuningSetsArgs, opts?: pulumi.InvokeOptions): Promise<GetManagedDatabaseSqlTuningSetsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:DatabaseManagement/getManagedDatabaseSqlTuningSets:getManagedDatabaseSqlTuningSets", {
        "filters": args.filters,
        "managedDatabaseId": args.managedDatabaseId,
        "nameContains": args.nameContains,
        "opcNamedCredentialId": args.opcNamedCredentialId,
        "owner": args.owner,
    }, opts);
}

/**
 * A collection of arguments for invoking getManagedDatabaseSqlTuningSets.
 */
export interface GetManagedDatabaseSqlTuningSetsArgs {
    filters?: inputs.DatabaseManagement.GetManagedDatabaseSqlTuningSetsFilter[];
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
     */
    managedDatabaseId: string;
    /**
     * Allow searching the name of the SQL tuning set by partial matching. The search is case insensitive.
     */
    nameContains?: string;
    /**
     * The OCID of the Named Credential.
     */
    opcNamedCredentialId?: string;
    /**
     * The owner of the SQL tuning set.
     */
    owner?: string;
}

/**
 * A collection of values returned by getManagedDatabaseSqlTuningSets.
 */
export interface GetManagedDatabaseSqlTuningSetsResult {
    readonly filters?: outputs.DatabaseManagement.GetManagedDatabaseSqlTuningSetsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
     */
    readonly managedDatabaseId: string;
    readonly nameContains?: string;
    readonly opcNamedCredentialId?: string;
    /**
     * The owner of the SQL tuning set.
     */
    readonly owner?: string;
    /**
     * The list of sql_tuning_set_collection.
     */
    readonly sqlTuningSetCollections: outputs.DatabaseManagement.GetManagedDatabaseSqlTuningSetsSqlTuningSetCollection[];
}
/**
 * This data source provides the list of Managed Database Sql Tuning Sets in Oracle Cloud Infrastructure Database Management service.
 *
 * Lists the SQL tuning sets for the specified Managed Database.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testManagedDatabaseSqlTuningSets = oci.DatabaseManagement.getManagedDatabaseSqlTuningSets({
 *     managedDatabaseId: testManagedDatabase.id,
 *     nameContains: managedDatabaseSqlTuningSetNameContains,
 *     opcNamedCredentialId: managedDatabaseSqlTuningSetOpcNamedCredentialId,
 *     owner: managedDatabaseSqlTuningSetOwner,
 * });
 * ```
 */
export function getManagedDatabaseSqlTuningSetsOutput(args: GetManagedDatabaseSqlTuningSetsOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetManagedDatabaseSqlTuningSetsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:DatabaseManagement/getManagedDatabaseSqlTuningSets:getManagedDatabaseSqlTuningSets", {
        "filters": args.filters,
        "managedDatabaseId": args.managedDatabaseId,
        "nameContains": args.nameContains,
        "opcNamedCredentialId": args.opcNamedCredentialId,
        "owner": args.owner,
    }, opts);
}

/**
 * A collection of arguments for invoking getManagedDatabaseSqlTuningSets.
 */
export interface GetManagedDatabaseSqlTuningSetsOutputArgs {
    filters?: pulumi.Input<pulumi.Input<inputs.DatabaseManagement.GetManagedDatabaseSqlTuningSetsFilterArgs>[]>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
     */
    managedDatabaseId: pulumi.Input<string>;
    /**
     * Allow searching the name of the SQL tuning set by partial matching. The search is case insensitive.
     */
    nameContains?: pulumi.Input<string>;
    /**
     * The OCID of the Named Credential.
     */
    opcNamedCredentialId?: pulumi.Input<string>;
    /**
     * The owner of the SQL tuning set.
     */
    owner?: pulumi.Input<string>;
}
