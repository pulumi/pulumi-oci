// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Services in Oracle Cloud Infrastructure Core service.
 *
 * Lists the available [Service](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Service/) objects that you can enable for a
 * service gateway in this region.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testServices = oci.Core.getServices({});
 * ```
 */
export function getServices(args?: GetServicesArgs, opts?: pulumi.InvokeOptions): Promise<GetServicesResult> {
    args = args || {};
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Core/getServices:getServices", {
        "filters": args.filters,
    }, opts);
}

/**
 * A collection of arguments for invoking getServices.
 */
export interface GetServicesArgs {
    filters?: inputs.Core.GetServicesFilter[];
}

/**
 * A collection of values returned by getServices.
 */
export interface GetServicesResult {
    readonly filters?: outputs.Core.GetServicesFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The list of services.
     */
    readonly services: outputs.Core.GetServicesService[];
}
/**
 * This data source provides the list of Services in Oracle Cloud Infrastructure Core service.
 *
 * Lists the available [Service](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Service/) objects that you can enable for a
 * service gateway in this region.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testServices = oci.Core.getServices({});
 * ```
 */
export function getServicesOutput(args?: GetServicesOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetServicesResult> {
    args = args || {};
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Core/getServices:getServices", {
        "filters": args.filters,
    }, opts);
}

/**
 * A collection of arguments for invoking getServices.
 */
export interface GetServicesOutputArgs {
    filters?: pulumi.Input<pulumi.Input<inputs.Core.GetServicesFilterArgs>[]>;
}
