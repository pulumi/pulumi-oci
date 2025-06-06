// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Metastore resource in Oracle Cloud Infrastructure Data Catalog service.
 *
 * Gets a metastore by identifier.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testMetastore = oci.DataCatalog.getMetastore({
 *     metastoreId: testMetastoreOciDatacatalogMetastore.id,
 * });
 * ```
 */
export function getMetastore(args: GetMetastoreArgs, opts?: pulumi.InvokeOptions): Promise<GetMetastoreResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:DataCatalog/getMetastore:getMetastore", {
        "metastoreId": args.metastoreId,
    }, opts);
}

/**
 * A collection of arguments for invoking getMetastore.
 */
export interface GetMetastoreArgs {
    /**
     * The metastore's OCID.
     */
    metastoreId: string;
}

/**
 * A collection of values returned by getMetastore.
 */
export interface GetMetastoreResult {
    /**
     * OCID of the compartment which holds the metastore.
     */
    readonly compartmentId: string;
    /**
     * Location under which external tables will be created by default. This references Object Storage using an HDFS URI format. Example: oci://bucket@namespace/sub-dir/
     */
    readonly defaultExternalTableLocation: string;
    /**
     * Location under which managed tables will be created by default. This references Object Storage using an HDFS URI format. Example: oci://bucket@namespace/sub-dir/
     */
    readonly defaultManagedTableLocation: string;
    /**
     * Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{"foo-namespace.bar-key": "value"}`
     */
    readonly definedTags: {[key: string]: string};
    /**
     * Mutable name of the metastore.
     */
    readonly displayName: string;
    /**
     * Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    readonly freeformTags: {[key: string]: string};
    /**
     * The metastore's OCID.
     */
    readonly id: string;
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     */
    readonly lifecycleDetails: string;
    /**
     * Locks associated with this resource.
     */
    readonly locks: outputs.DataCatalog.GetMetastoreLock[];
    readonly metastoreId: string;
    /**
     * The current state of the metastore.
     */
    readonly state: string;
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    readonly systemTags: {[key: string]: string};
    /**
     * Time at which the metastore was created. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
     */
    readonly timeCreated: string;
    /**
     * Time at which the metastore was last modified. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
     */
    readonly timeUpdated: string;
}
/**
 * This data source provides details about a specific Metastore resource in Oracle Cloud Infrastructure Data Catalog service.
 *
 * Gets a metastore by identifier.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testMetastore = oci.DataCatalog.getMetastore({
 *     metastoreId: testMetastoreOciDatacatalogMetastore.id,
 * });
 * ```
 */
export function getMetastoreOutput(args: GetMetastoreOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetMetastoreResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:DataCatalog/getMetastore:getMetastore", {
        "metastoreId": args.metastoreId,
    }, opts);
}

/**
 * A collection of arguments for invoking getMetastore.
 */
export interface GetMetastoreOutputArgs {
    /**
     * The metastore's OCID.
     */
    metastoreId: pulumi.Input<string>;
}
