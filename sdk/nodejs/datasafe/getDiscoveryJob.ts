// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Discovery Job resource in Oracle Cloud Infrastructure Data Safe service.
 *
 * Gets the details of the specified discovery job.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDiscoveryJob = oci.DataSafe.getDiscoveryJob({
 *     discoveryJobId: testDiscoveryJobOciDataSafeDiscoveryJob.id,
 * });
 * ```
 */
export function getDiscoveryJob(args: GetDiscoveryJobArgs, opts?: pulumi.InvokeOptions): Promise<GetDiscoveryJobResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:DataSafe/getDiscoveryJob:getDiscoveryJob", {
        "discoveryJobId": args.discoveryJobId,
    }, opts);
}

/**
 * A collection of arguments for invoking getDiscoveryJob.
 */
export interface GetDiscoveryJobArgs {
    /**
     * The OCID of the discovery job.
     */
    discoveryJobId: string;
}

/**
 * A collection of values returned by getDiscoveryJob.
 */
export interface GetDiscoveryJobResult {
    /**
     * The OCID of the compartment that contains the discovery job.
     */
    readonly compartmentId: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm) Example: `{"Operations.CostCenter": "42"}`
     */
    readonly definedTags: {[key: string]: string};
    readonly discoveryJobId: string;
    /**
     * The type of the discovery job. It defines the job's scope. NEW identifies new sensitive columns in the target database that are not in the sensitive data model. DELETED identifies columns that are present in the sensitive data model but have been deleted from the target database. MODIFIED identifies columns that are present in the target database as well as the sensitive data model but some of their attributes have been modified. ALL covers all the above three scenarios and reports new, deleted and modified columns.
     */
    readonly discoveryType: string;
    /**
     * The display name of the discovery job.
     */
    readonly displayName: string;
    /**
     * Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
     */
    readonly freeformTags: {[key: string]: string};
    /**
     * The OCID of the discovery job.
     */
    readonly id: string;
    /**
     * Indicates if the discovery job should identify potential application-level (non-dictionary) referential relationships between columns. Note that data discovery automatically identifies and adds database-level (dictionary-defined) relationships. This option helps identify application-level relationships that are not defined in the database dictionary, which in turn, helps identify additional sensitive columns and preserve referential integrity during data masking. It's disabled by default and should be used only if there is a need to identify application-level relationships.
     */
    readonly isAppDefinedRelationDiscoveryEnabled: boolean;
    /**
     * Indicates if all the schemas in the associated target database are used for data discovery. If it is set to true, sensitive data is discovered in all schemas (except for schemas maintained by Oracle).
     */
    readonly isIncludeAllSchemas: boolean;
    /**
     * Indicates if all the existing sensitive types are used for data discovery. If it's set to true, the sensitiveTypeIdsForDiscovery attribute is ignored and all sensitive types are used.
     */
    readonly isIncludeAllSensitiveTypes: boolean;
    /**
     * Indicates if the discovery job should collect and store sample data values for the discovered columns. Sample data helps review the discovered columns and ensure that they actually contain sensitive data. As it collects original data from the target database, it's disabled by default and should be used only if it's acceptable to store sample data in Data Safe's repository in Oracle Cloud. Note that sample data values are not collected for columns with the following data types: LONG, LOB, RAW, XMLTYPE and BFILE.
     */
    readonly isSampleDataCollectionEnabled: boolean;
    /**
     * The schemas used for data discovery.
     */
    readonly schemasForDiscoveries: string[];
    /**
     * The OCID of the sensitive data model associated with the discovery job.
     */
    readonly sensitiveDataModelId: string;
    /**
     * The OCIDs of the sensitive type groups to be used by data discovery jobs.
     */
    readonly sensitiveTypeGroupIdsForDiscoveries: string[];
    /**
     * The OCIDs of the sensitive types used for data discovery.
     */
    readonly sensitiveTypeIdsForDiscoveries: string[];
    /**
     * The current state of the discovery job.
     */
    readonly state: string;
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    readonly systemTags: {[key: string]: string};
    /**
     * The data discovery jobs will scan the tables specified here, including both schemas and tables.
     */
    readonly tablesForDiscoveries: outputs.DataSafe.GetDiscoveryJobTablesForDiscovery[];
    /**
     * The OCID of the target database associated with the discovery job.
     */
    readonly targetId: string;
    /**
     * The date and time the discovery job finished, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339)..
     */
    readonly timeFinished: string;
    /**
     * The date and time the discovery job started, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     */
    readonly timeStarted: string;
    /**
     * The total number of columns scanned by the discovery job.
     */
    readonly totalColumnsScanned: string;
    /**
     * The total number of deleted sensitive columns identified by the discovery job.
     */
    readonly totalDeletedSensitiveColumns: string;
    /**
     * The total number of modified sensitive columns identified by the discovery job.
     */
    readonly totalModifiedSensitiveColumns: string;
    /**
     * The total number of new sensitive columns identified by the discovery job.
     */
    readonly totalNewSensitiveColumns: string;
    /**
     * The total number of objects (tables and editioning views) scanned by the discovery job.
     */
    readonly totalObjectsScanned: string;
    /**
     * The total number of schemas scanned by the discovery job.
     */
    readonly totalSchemasScanned: string;
}
/**
 * This data source provides details about a specific Discovery Job resource in Oracle Cloud Infrastructure Data Safe service.
 *
 * Gets the details of the specified discovery job.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDiscoveryJob = oci.DataSafe.getDiscoveryJob({
 *     discoveryJobId: testDiscoveryJobOciDataSafeDiscoveryJob.id,
 * });
 * ```
 */
export function getDiscoveryJobOutput(args: GetDiscoveryJobOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetDiscoveryJobResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:DataSafe/getDiscoveryJob:getDiscoveryJob", {
        "discoveryJobId": args.discoveryJobId,
    }, opts);
}

/**
 * A collection of arguments for invoking getDiscoveryJob.
 */
export interface GetDiscoveryJobOutputArgs {
    /**
     * The OCID of the discovery job.
     */
    discoveryJobId: pulumi.Input<string>;
}
