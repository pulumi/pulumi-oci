// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Internal Occm Demand Signal Catalog resource in Oracle Cloud Infrastructure Capacity Management service.
 *
 * This API helps in getting the details about a specific occm demand signal catalog.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testInternalOccmDemandSignalCatalog = oci.CapacityManagement.getInternalOccmDemandSignalCatalog({
 *     occmDemandSignalCatalogId: testCatalog.id,
 * });
 * ```
 */
export function getInternalOccmDemandSignalCatalog(args: GetInternalOccmDemandSignalCatalogArgs, opts?: pulumi.InvokeOptions): Promise<GetInternalOccmDemandSignalCatalogResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:CapacityManagement/getInternalOccmDemandSignalCatalog:getInternalOccmDemandSignalCatalog", {
        "occmDemandSignalCatalogId": args.occmDemandSignalCatalogId,
    }, opts);
}

/**
 * A collection of arguments for invoking getInternalOccmDemandSignalCatalog.
 */
export interface GetInternalOccmDemandSignalCatalogArgs {
    /**
     * The OCID of the demand signal catalog.
     */
    occmDemandSignalCatalogId: string;
}

/**
 * A collection of values returned by getInternalOccmDemandSignalCatalog.
 */
export interface GetInternalOccmDemandSignalCatalogResult {
    /**
     * compartment id from where demand signal catalog is created.
     */
    readonly compartmentId: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    readonly definedTags: {[key: string]: string};
    /**
     * description of demand signal catalog.
     */
    readonly description: string;
    /**
     * displayName of demand signal catalog.
     */
    readonly displayName: string;
    /**
     * Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    readonly freeformTags: {[key: string]: string};
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The customer group OCID to which the availability catalog belongs.
     */
    readonly occCustomerGroupId: string;
    readonly occmDemandSignalCatalogId: string;
    /**
     * The current lifecycle state of the resource.
     */
    readonly state: string;
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    readonly systemTags: {[key: string]: string};
    /**
     * The time when the demand signal catalog was created.
     */
    readonly timeCreated: string;
    /**
     * The time when the demand signal catalog was last updated.
     */
    readonly timeUpdated: string;
}
/**
 * This data source provides details about a specific Internal Occm Demand Signal Catalog resource in Oracle Cloud Infrastructure Capacity Management service.
 *
 * This API helps in getting the details about a specific occm demand signal catalog.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testInternalOccmDemandSignalCatalog = oci.CapacityManagement.getInternalOccmDemandSignalCatalog({
 *     occmDemandSignalCatalogId: testCatalog.id,
 * });
 * ```
 */
export function getInternalOccmDemandSignalCatalogOutput(args: GetInternalOccmDemandSignalCatalogOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetInternalOccmDemandSignalCatalogResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:CapacityManagement/getInternalOccmDemandSignalCatalog:getInternalOccmDemandSignalCatalog", {
        "occmDemandSignalCatalogId": args.occmDemandSignalCatalogId,
    }, opts);
}

/**
 * A collection of arguments for invoking getInternalOccmDemandSignalCatalog.
 */
export interface GetInternalOccmDemandSignalCatalogOutputArgs {
    /**
     * The OCID of the demand signal catalog.
     */
    occmDemandSignalCatalogId: pulumi.Input<string>;
}
