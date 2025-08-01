// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Occm Demand Signal Catalog Resources in Oracle Cloud Infrastructure Capacity Management service.
 *
 * This API will list all the  resources across all demand signal catalogs for a given namespace and customer group containing the caller compartment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testOccmDemandSignalCatalogResources = oci.CapacityManagement.getOccmDemandSignalCatalogResources({
 *     compartmentId: compartmentId,
 *     demandSignalNamespace: occmDemandSignalCatalogResourceDemandSignalNamespace,
 *     name: occmDemandSignalCatalogResourceName,
 * });
 * ```
 */
export function getOccmDemandSignalCatalogResources(args: GetOccmDemandSignalCatalogResourcesArgs, opts?: pulumi.InvokeOptions): Promise<GetOccmDemandSignalCatalogResourcesResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:CapacityManagement/getOccmDemandSignalCatalogResources:getOccmDemandSignalCatalogResources", {
        "compartmentId": args.compartmentId,
        "demandSignalNamespace": args.demandSignalNamespace,
        "filters": args.filters,
        "name": args.name,
    }, opts);
}

/**
 * A collection of arguments for invoking getOccmDemandSignalCatalogResources.
 */
export interface GetOccmDemandSignalCatalogResourcesArgs {
    /**
     * The ocid of the compartment or tenancy in which resources are to be listed. This will also be used for authorization purposes.
     */
    compartmentId: string;
    /**
     * A query parameter to filter the list of demand signal catalog resources based on the namespace.
     */
    demandSignalNamespace?: string;
    filters?: inputs.CapacityManagement.GetOccmDemandSignalCatalogResourcesFilter[];
    /**
     * A query parameter to filter the list of demand signal catalog resource based on the resource name.
     */
    name?: string;
}

/**
 * A collection of values returned by getOccmDemandSignalCatalogResources.
 */
export interface GetOccmDemandSignalCatalogResourcesResult {
    /**
     * The OCID of the tenancy from which the request to create the demand signal was made.
     */
    readonly compartmentId: string;
    readonly demandSignalNamespace?: string;
    readonly filters?: outputs.CapacityManagement.GetOccmDemandSignalCatalogResourcesFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The name of the Oracle Cloud Infrastructure resource that you want to request.
     */
    readonly name?: string;
    /**
     * The list of occm_demand_signal_catalog_resource_collection.
     */
    readonly occmDemandSignalCatalogResourceCollections: outputs.CapacityManagement.GetOccmDemandSignalCatalogResourcesOccmDemandSignalCatalogResourceCollection[];
}
/**
 * This data source provides the list of Occm Demand Signal Catalog Resources in Oracle Cloud Infrastructure Capacity Management service.
 *
 * This API will list all the  resources across all demand signal catalogs for a given namespace and customer group containing the caller compartment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testOccmDemandSignalCatalogResources = oci.CapacityManagement.getOccmDemandSignalCatalogResources({
 *     compartmentId: compartmentId,
 *     demandSignalNamespace: occmDemandSignalCatalogResourceDemandSignalNamespace,
 *     name: occmDemandSignalCatalogResourceName,
 * });
 * ```
 */
export function getOccmDemandSignalCatalogResourcesOutput(args: GetOccmDemandSignalCatalogResourcesOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetOccmDemandSignalCatalogResourcesResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:CapacityManagement/getOccmDemandSignalCatalogResources:getOccmDemandSignalCatalogResources", {
        "compartmentId": args.compartmentId,
        "demandSignalNamespace": args.demandSignalNamespace,
        "filters": args.filters,
        "name": args.name,
    }, opts);
}

/**
 * A collection of arguments for invoking getOccmDemandSignalCatalogResources.
 */
export interface GetOccmDemandSignalCatalogResourcesOutputArgs {
    /**
     * The ocid of the compartment or tenancy in which resources are to be listed. This will also be used for authorization purposes.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * A query parameter to filter the list of demand signal catalog resources based on the namespace.
     */
    demandSignalNamespace?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.CapacityManagement.GetOccmDemandSignalCatalogResourcesFilterArgs>[]>;
    /**
     * A query parameter to filter the list of demand signal catalog resource based on the resource name.
     */
    name?: pulumi.Input<string>;
}
