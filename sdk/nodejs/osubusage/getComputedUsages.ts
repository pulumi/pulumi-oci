// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Computed Usages in Oracle Cloud Infrastructure Osub Usage service.
 *
 * This is a collection API which returns a list of Computed Usages for given filters.
 */
export function getComputedUsages(args: GetComputedUsagesArgs, opts?: pulumi.InvokeOptions): Promise<GetComputedUsagesResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:OsubUsage/getComputedUsages:getComputedUsages", {
        "compartmentId": args.compartmentId,
        "computedProduct": args.computedProduct,
        "filters": args.filters,
        "parentProduct": args.parentProduct,
        "subscriptionId": args.subscriptionId,
        "timeFrom": args.timeFrom,
        "timeTo": args.timeTo,
        "xOneOriginRegion": args.xOneOriginRegion,
    }, opts);
}

/**
 * A collection of arguments for invoking getComputedUsages.
 */
export interface GetComputedUsagesArgs {
    /**
     * The OCID of the root compartment.
     */
    compartmentId: string;
    /**
     * Product part number for Computed Usage .
     */
    computedProduct?: string;
    filters?: inputs.OsubUsage.GetComputedUsagesFilter[];
    /**
     * Product part number for subscribed service line, called parent product.
     */
    parentProduct?: string;
    /**
     * Subscription Id is an identifier associated to the service used for filter the Computed Usage in SPM.
     */
    subscriptionId: string;
    /**
     * Initial date to filter Computed Usage data in SPM. In the case of non aggregated data the time period between of fromDate and toDate , expressed in RFC 3339 timestamp format.
     */
    timeFrom: string;
    /**
     * Final date to filter Computed Usage data in SPM, expressed in RFC 3339 timestamp format.
     */
    timeTo: string;
    /**
     * The Oracle Cloud Infrastructure home region name in case home region is not us-ashburn-1 (IAD), e.g. ap-mumbai-1, us-phoenix-1 etc.
     */
    xOneOriginRegion?: string;
}

/**
 * A collection of values returned by getComputedUsages.
 */
export interface GetComputedUsagesResult {
    readonly compartmentId: string;
    readonly computedProduct?: string;
    /**
     * The list of computed_usages.
     */
    readonly computedUsages: outputs.OsubUsage.GetComputedUsagesComputedUsage[];
    readonly filters?: outputs.OsubUsage.GetComputedUsagesFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * Product description
     */
    readonly parentProduct?: string;
    readonly subscriptionId: string;
    readonly timeFrom: string;
    readonly timeTo: string;
    readonly xOneOriginRegion?: string;
}

export function getComputedUsagesOutput(args: GetComputedUsagesOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetComputedUsagesResult> {
    return pulumi.output(args).apply(a => getComputedUsages(a, opts))
}

/**
 * A collection of arguments for invoking getComputedUsages.
 */
export interface GetComputedUsagesOutputArgs {
    /**
     * The OCID of the root compartment.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * Product part number for Computed Usage .
     */
    computedProduct?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.OsubUsage.GetComputedUsagesFilterArgs>[]>;
    /**
     * Product part number for subscribed service line, called parent product.
     */
    parentProduct?: pulumi.Input<string>;
    /**
     * Subscription Id is an identifier associated to the service used for filter the Computed Usage in SPM.
     */
    subscriptionId: pulumi.Input<string>;
    /**
     * Initial date to filter Computed Usage data in SPM. In the case of non aggregated data the time period between of fromDate and toDate , expressed in RFC 3339 timestamp format.
     */
    timeFrom: pulumi.Input<string>;
    /**
     * Final date to filter Computed Usage data in SPM, expressed in RFC 3339 timestamp format.
     */
    timeTo: pulumi.Input<string>;
    /**
     * The Oracle Cloud Infrastructure home region name in case home region is not us-ashburn-1 (IAD), e.g. ap-mumbai-1, us-phoenix-1 etc.
     */
    xOneOriginRegion?: pulumi.Input<string>;
}