// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of App Catalog Listing Resource Versions in Oracle Cloud Infrastructure Core service.
 *
 * Gets all resource versions for a particular listing.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testAppCatalogListingResourceVersions = oci.Core.getAppCatalogListingResourceVersions({
 *     listingId: data.oci_core_app_catalog_listing.test_listing.id,
 * });
 * ```
 */
export function getAppCatalogListingResourceVersions(args: GetAppCatalogListingResourceVersionsArgs, opts?: pulumi.InvokeOptions): Promise<GetAppCatalogListingResourceVersionsResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:Core/getAppCatalogListingResourceVersions:getAppCatalogListingResourceVersions", {
        "filters": args.filters,
        "listingId": args.listingId,
    }, opts);
}

/**
 * A collection of arguments for invoking getAppCatalogListingResourceVersions.
 */
export interface GetAppCatalogListingResourceVersionsArgs {
    filters?: inputs.Core.GetAppCatalogListingResourceVersionsFilter[];
    /**
     * The OCID of the listing.
     */
    listingId: string;
}

/**
 * A collection of values returned by getAppCatalogListingResourceVersions.
 */
export interface GetAppCatalogListingResourceVersionsResult {
    /**
     * The list of app_catalog_listing_resource_versions.
     */
    readonly appCatalogListingResourceVersions: outputs.Core.GetAppCatalogListingResourceVersionsAppCatalogListingResourceVersion[];
    readonly filters?: outputs.Core.GetAppCatalogListingResourceVersionsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The OCID of the listing this resource version belongs to.
     */
    readonly listingId: string;
}

export function getAppCatalogListingResourceVersionsOutput(args: GetAppCatalogListingResourceVersionsOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetAppCatalogListingResourceVersionsResult> {
    return pulumi.output(args).apply(a => getAppCatalogListingResourceVersions(a, opts))
}

/**
 * A collection of arguments for invoking getAppCatalogListingResourceVersions.
 */
export interface GetAppCatalogListingResourceVersionsOutputArgs {
    filters?: pulumi.Input<pulumi.Input<inputs.Core.GetAppCatalogListingResourceVersionsFilterArgs>[]>;
    /**
     * The OCID of the listing.
     */
    listingId: pulumi.Input<string>;
}