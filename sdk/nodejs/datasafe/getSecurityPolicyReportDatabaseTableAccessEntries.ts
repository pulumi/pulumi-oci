// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Security Policy Report Database Table Access Entries in Oracle Cloud Infrastructure Data Safe service.
 *
 * Retrieves a list of all database table access entries in Data Safe.
 *
 * The ListDatabaseTableAccessEntries operation returns only the database table access reports for the specified security policy report.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testSecurityPolicyReportDatabaseTableAccessEntries = oci.DataSafe.getSecurityPolicyReportDatabaseTableAccessEntries({
 *     securityPolicyReportId: testSecurityPolicyReport.id,
 *     scimQuery: securityPolicyReportDatabaseTableAccessEntryScimQuery,
 * });
 * ```
 */
export function getSecurityPolicyReportDatabaseTableAccessEntries(args: GetSecurityPolicyReportDatabaseTableAccessEntriesArgs, opts?: pulumi.InvokeOptions): Promise<GetSecurityPolicyReportDatabaseTableAccessEntriesResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:DataSafe/getSecurityPolicyReportDatabaseTableAccessEntries:getSecurityPolicyReportDatabaseTableAccessEntries", {
        "filters": args.filters,
        "scimQuery": args.scimQuery,
        "securityPolicyReportId": args.securityPolicyReportId,
    }, opts);
}

/**
 * A collection of arguments for invoking getSecurityPolicyReportDatabaseTableAccessEntries.
 */
export interface GetSecurityPolicyReportDatabaseTableAccessEntriesArgs {
    filters?: inputs.DataSafe.GetSecurityPolicyReportDatabaseTableAccessEntriesFilter[];
    /**
     * The scimQuery query parameter accepts filter expressions that use the syntax described in Section 3.2.2.2 of the System for Cross-Domain Identity Management (SCIM) specification, which is available at [RFC3339](https://tools.ietf.org/html/draft-ietf-scim-api-12). In SCIM filtering expressions, text, date, and time values must be enclosed in quotation marks, with date and time values using ISO-8601 format. (Numeric and boolean values should not be quoted.)
     *
     * **Example:** query=(accessType eq 'SELECT') and (grantee eq 'ADMIN')
     */
    scimQuery?: string;
    /**
     * The OCID of the security policy report resource.
     */
    securityPolicyReportId: string;
}

/**
 * A collection of values returned by getSecurityPolicyReportDatabaseTableAccessEntries.
 */
export interface GetSecurityPolicyReportDatabaseTableAccessEntriesResult {
    /**
     * The list of database_table_access_entry_collection.
     */
    readonly databaseTableAccessEntryCollections: outputs.DataSafe.GetSecurityPolicyReportDatabaseTableAccessEntriesDatabaseTableAccessEntryCollection[];
    readonly filters?: outputs.DataSafe.GetSecurityPolicyReportDatabaseTableAccessEntriesFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    readonly scimQuery?: string;
    readonly securityPolicyReportId: string;
}
/**
 * This data source provides the list of Security Policy Report Database Table Access Entries in Oracle Cloud Infrastructure Data Safe service.
 *
 * Retrieves a list of all database table access entries in Data Safe.
 *
 * The ListDatabaseTableAccessEntries operation returns only the database table access reports for the specified security policy report.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testSecurityPolicyReportDatabaseTableAccessEntries = oci.DataSafe.getSecurityPolicyReportDatabaseTableAccessEntries({
 *     securityPolicyReportId: testSecurityPolicyReport.id,
 *     scimQuery: securityPolicyReportDatabaseTableAccessEntryScimQuery,
 * });
 * ```
 */
export function getSecurityPolicyReportDatabaseTableAccessEntriesOutput(args: GetSecurityPolicyReportDatabaseTableAccessEntriesOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetSecurityPolicyReportDatabaseTableAccessEntriesResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:DataSafe/getSecurityPolicyReportDatabaseTableAccessEntries:getSecurityPolicyReportDatabaseTableAccessEntries", {
        "filters": args.filters,
        "scimQuery": args.scimQuery,
        "securityPolicyReportId": args.securityPolicyReportId,
    }, opts);
}

/**
 * A collection of arguments for invoking getSecurityPolicyReportDatabaseTableAccessEntries.
 */
export interface GetSecurityPolicyReportDatabaseTableAccessEntriesOutputArgs {
    filters?: pulumi.Input<pulumi.Input<inputs.DataSafe.GetSecurityPolicyReportDatabaseTableAccessEntriesFilterArgs>[]>;
    /**
     * The scimQuery query parameter accepts filter expressions that use the syntax described in Section 3.2.2.2 of the System for Cross-Domain Identity Management (SCIM) specification, which is available at [RFC3339](https://tools.ietf.org/html/draft-ietf-scim-api-12). In SCIM filtering expressions, text, date, and time values must be enclosed in quotation marks, with date and time values using ISO-8601 format. (Numeric and boolean values should not be quoted.)
     *
     * **Example:** query=(accessType eq 'SELECT') and (grantee eq 'ADMIN')
     */
    scimQuery?: pulumi.Input<string>;
    /**
     * The OCID of the security policy report resource.
     */
    securityPolicyReportId: pulumi.Input<string>;
}
