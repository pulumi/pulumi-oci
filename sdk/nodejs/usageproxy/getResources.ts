// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Resources in Oracle Cloud Infrastructure Usage Proxy service.
 *
 * Returns the resource details for a service
 * > **Important**: Calls to this API will only succeed against the endpoint in the home region.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testResources = oci.UsageProxy.getResources({
 *     compartmentId: _var.compartment_id,
 *     serviceName: oci_core_service.test_service.name,
 *     entitlementId: oci_usage_proxy_entitlement.test_entitlement.id,
 * });
 * ```
 */
export function getResources(args: GetResourcesArgs, opts?: pulumi.InvokeOptions): Promise<GetResourcesResult> {

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:UsageProxy/getResources:getResources", {
        "compartmentId": args.compartmentId,
        "entitlementId": args.entitlementId,
        "filters": args.filters,
        "serviceName": args.serviceName,
    }, opts);
}

/**
 * A collection of arguments for invoking getResources.
 */
export interface GetResourcesArgs {
    /**
     * The OCID of the root compartment.
     */
    compartmentId: string;
    /**
     * Subscription or entitlement Id.
     */
    entitlementId?: string;
    filters?: inputs.UsageProxy.GetResourcesFilter[];
    /**
     * Service Name.
     */
    serviceName: string;
}

/**
 * A collection of values returned by getResources.
 */
export interface GetResourcesResult {
    readonly compartmentId: string;
    readonly entitlementId?: string;
    readonly filters?: outputs.UsageProxy.GetResourcesFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The list of resources_collection.
     */
    readonly resourcesCollections: outputs.UsageProxy.GetResourcesResourcesCollection[];
    readonly serviceName: string;
}
/**
 * This data source provides the list of Resources in Oracle Cloud Infrastructure Usage Proxy service.
 *
 * Returns the resource details for a service
 * > **Important**: Calls to this API will only succeed against the endpoint in the home region.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testResources = oci.UsageProxy.getResources({
 *     compartmentId: _var.compartment_id,
 *     serviceName: oci_core_service.test_service.name,
 *     entitlementId: oci_usage_proxy_entitlement.test_entitlement.id,
 * });
 * ```
 */
export function getResourcesOutput(args: GetResourcesOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetResourcesResult> {
    return pulumi.output(args).apply((a: any) => getResources(a, opts))
}

/**
 * A collection of arguments for invoking getResources.
 */
export interface GetResourcesOutputArgs {
    /**
     * The OCID of the root compartment.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * Subscription or entitlement Id.
     */
    entitlementId?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.UsageProxy.GetResourcesFilterArgs>[]>;
    /**
     * Service Name.
     */
    serviceName: pulumi.Input<string>;
}