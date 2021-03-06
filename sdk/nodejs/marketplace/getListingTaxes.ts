// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Listing Taxes in Oracle Cloud Infrastructure Marketplace service.
 *
 * Returns list of all tax implications that current tenant may be liable to once they launch the listing.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testListingTaxes = oci.Marketplace.getListingTaxes({
 *     listingId: oci_marketplace_listing.test_listing.id,
 *     compartmentId: _var.compartment_id,
 * });
 * ```
 */
export function getListingTaxes(args: GetListingTaxesArgs, opts?: pulumi.InvokeOptions): Promise<GetListingTaxesResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:Marketplace/getListingTaxes:getListingTaxes", {
        "compartmentId": args.compartmentId,
        "filters": args.filters,
        "listingId": args.listingId,
    }, opts);
}

/**
 * A collection of arguments for invoking getListingTaxes.
 */
export interface GetListingTaxesArgs {
    /**
     * The unique identifier for the compartment.
     */
    compartmentId?: string;
    filters?: inputs.Marketplace.GetListingTaxesFilter[];
    /**
     * The unique identifier for the listing.
     */
    listingId: string;
}

/**
 * A collection of values returned by getListingTaxes.
 */
export interface GetListingTaxesResult {
    readonly compartmentId?: string;
    readonly filters?: outputs.Marketplace.GetListingTaxesFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    readonly listingId: string;
    /**
     * The list of taxes.
     */
    readonly taxes: outputs.Marketplace.GetListingTaxesTax[];
}

export function getListingTaxesOutput(args: GetListingTaxesOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetListingTaxesResult> {
    return pulumi.output(args).apply(a => getListingTaxes(a, opts))
}

/**
 * A collection of arguments for invoking getListingTaxes.
 */
export interface GetListingTaxesOutputArgs {
    /**
     * The unique identifier for the compartment.
     */
    compartmentId?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.Marketplace.GetListingTaxesFilterArgs>[]>;
    /**
     * The unique identifier for the listing.
     */
    listingId: pulumi.Input<string>;
}
