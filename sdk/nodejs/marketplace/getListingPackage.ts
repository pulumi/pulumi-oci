// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Listing Package resource in Oracle Cloud Infrastructure Marketplace service.
 *
 * Get the details of the specified version of a package, including information needed to launch the package.
 *
 * If you plan to launch an instance from an image listing, you must first subscribe to the listing. When
 * you launch the instance, you also need to provide the image ID of the listing resource version that you want.
 *
 * Subscribing to the listing requires you to first get a signature from the terms of use agreement for the
 * listing resource version. To get the signature, issue a [GetAppCatalogListingAgreements](https://docs.cloud.oracle.com/en-us/iaas/api/#/en/iaas/latest/AppCatalogListingResourceVersionAgreements/GetAppCatalogListingAgreements) API call.
 * The [AppCatalogListingResourceVersionAgreements](https://docs.cloud.oracle.com/en-us/iaas/api/#/en/iaas/latest/AppCatalogListingResourceVersionAgreements) object, including
 * its signature, is returned in the response. With the signature for the terms of use agreement for the desired
 * listing resource version, create a subscription by issuing a
 * [CreateAppCatalogSubscription](https://docs.cloud.oracle.com/en-us/iaas/api/#/en/iaas/latest/AppCatalogSubscription/CreateAppCatalogSubscription) API call.
 *
 * To get the image ID to launch an instance, issue a [GetAppCatalogListingResourceVersion](https://docs.cloud.oracle.com/en-us/iaas/api/#/en/iaas/latest/AppCatalogListingResourceVersion/GetAppCatalogListingResourceVersion) API call.
 * Lastly, to launch the instance, use the image ID of the listing resource version to issue a [LaunchInstance](https://docs.cloud.oracle.com/en-us/iaas/api/#/en/iaas/latest/Instance/LaunchInstance) API call.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testListingPackage = oci.Marketplace.getListingPackage({
 *     listingId: testListing.id,
 *     packageVersion: listingPackagePackageVersion,
 *     compartmentId: compartmentId,
 * });
 * ```
 */
export function getListingPackage(args: GetListingPackageArgs, opts?: pulumi.InvokeOptions): Promise<GetListingPackageResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Marketplace/getListingPackage:getListingPackage", {
        "compartmentId": args.compartmentId,
        "listingId": args.listingId,
        "packageVersion": args.packageVersion,
    }, opts);
}

/**
 * A collection of arguments for invoking getListingPackage.
 */
export interface GetListingPackageArgs {
    /**
     * The unique identifier for the compartment.
     */
    compartmentId?: string;
    /**
     * The unique identifier for the listing.
     */
    listingId: string;
    /**
     * The version of the package. Package versions are unique within a listing.
     */
    packageVersion: string;
}

/**
 * A collection of values returned by getListingPackage.
 */
export interface GetListingPackageResult {
    /**
     * The ID of the listing resource associated with this listing package. For more information, see [AppCatalogListing](https://docs.cloud.oracle.com/en-us/iaas/api/#/en/iaas/latest/AppCatalogListing/) in the Core Services API.
     */
    readonly appCatalogListingId: string;
    /**
     * The resource version of the listing resource associated with this listing package.
     */
    readonly appCatalogListingResourceVersion: string;
    readonly compartmentId?: string;
    /**
     * A description of the variable.
     */
    readonly description: string;
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The ID of the image corresponding to the package.
     */
    readonly imageId: string;
    /**
     * The ID of the listing that the specified package belongs to.
     */
    readonly listingId: string;
    /**
     * The operating system used by the listing.
     */
    readonly operatingSystems: outputs.Marketplace.GetListingPackageOperatingSystem[];
    /**
     * The specified package's type.
     */
    readonly packageType: string;
    readonly packageVersion: string;
    /**
     * The model for pricing.
     */
    readonly pricings: outputs.Marketplace.GetListingPackagePricing[];
    /**
     * The regions where you can deploy the listing package. (Some packages have restrictions that limit their deployment to United States regions only.)
     */
    readonly regions: outputs.Marketplace.GetListingPackageRegion[];
    /**
     * The unique identifier for the package resource.
     */
    readonly resourceId: string;
    /**
     * Link to the orchestration resource.
     */
    readonly resourceLink: string;
    /**
     * The date and time this listing package was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
     */
    readonly timeCreated: string;
    /**
     * List of variables for the orchestration resource.
     */
    readonly variables: outputs.Marketplace.GetListingPackageVariable[];
    /**
     * The package version.
     */
    readonly version: string;
}
/**
 * This data source provides details about a specific Listing Package resource in Oracle Cloud Infrastructure Marketplace service.
 *
 * Get the details of the specified version of a package, including information needed to launch the package.
 *
 * If you plan to launch an instance from an image listing, you must first subscribe to the listing. When
 * you launch the instance, you also need to provide the image ID of the listing resource version that you want.
 *
 * Subscribing to the listing requires you to first get a signature from the terms of use agreement for the
 * listing resource version. To get the signature, issue a [GetAppCatalogListingAgreements](https://docs.cloud.oracle.com/en-us/iaas/api/#/en/iaas/latest/AppCatalogListingResourceVersionAgreements/GetAppCatalogListingAgreements) API call.
 * The [AppCatalogListingResourceVersionAgreements](https://docs.cloud.oracle.com/en-us/iaas/api/#/en/iaas/latest/AppCatalogListingResourceVersionAgreements) object, including
 * its signature, is returned in the response. With the signature for the terms of use agreement for the desired
 * listing resource version, create a subscription by issuing a
 * [CreateAppCatalogSubscription](https://docs.cloud.oracle.com/en-us/iaas/api/#/en/iaas/latest/AppCatalogSubscription/CreateAppCatalogSubscription) API call.
 *
 * To get the image ID to launch an instance, issue a [GetAppCatalogListingResourceVersion](https://docs.cloud.oracle.com/en-us/iaas/api/#/en/iaas/latest/AppCatalogListingResourceVersion/GetAppCatalogListingResourceVersion) API call.
 * Lastly, to launch the instance, use the image ID of the listing resource version to issue a [LaunchInstance](https://docs.cloud.oracle.com/en-us/iaas/api/#/en/iaas/latest/Instance/LaunchInstance) API call.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testListingPackage = oci.Marketplace.getListingPackage({
 *     listingId: testListing.id,
 *     packageVersion: listingPackagePackageVersion,
 *     compartmentId: compartmentId,
 * });
 * ```
 */
export function getListingPackageOutput(args: GetListingPackageOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetListingPackageResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Marketplace/getListingPackage:getListingPackage", {
        "compartmentId": args.compartmentId,
        "listingId": args.listingId,
        "packageVersion": args.packageVersion,
    }, opts);
}

/**
 * A collection of arguments for invoking getListingPackage.
 */
export interface GetListingPackageOutputArgs {
    /**
     * The unique identifier for the compartment.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * The unique identifier for the listing.
     */
    listingId: pulumi.Input<string>;
    /**
     * The version of the package. Package versions are unique within a listing.
     */
    packageVersion: pulumi.Input<string>;
}
