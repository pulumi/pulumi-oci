// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Internal Occm Demand Signal Catalog Resources in Oracle Cloud Infrastructure Capacity Management service.
 *
 * This API will list all the  resources across all demand signal catalogs for a given namespace and customer group.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testInternalOccmDemandSignalCatalogResources = oci.CapacityManagement.getInternalOccmDemandSignalCatalogResources({
 *     compartmentId: compartmentId,
 *     occCustomerGroupId: testOccCustomerGroup.id,
 *     occmDemandSignalCatalogId: testCatalog.id,
 *     demandSignalNamespace: internalOccmDemandSignalCatalogResourceDemandSignalNamespace,
 *     name: internalOccmDemandSignalCatalogResourceName,
 * });
 * ```
 */
export function getInternalOccmDemandSignalCatalogResources(args: GetInternalOccmDemandSignalCatalogResourcesArgs, opts?: pulumi.InvokeOptions): Promise<GetInternalOccmDemandSignalCatalogResourcesResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:CapacityManagement/getInternalOccmDemandSignalCatalogResources:getInternalOccmDemandSignalCatalogResources", {
        "compartmentId": args.compartmentId,
        "demandSignalNamespace": args.demandSignalNamespace,
        "filters": args.filters,
        "name": args.name,
        "occCustomerGroupId": args.occCustomerGroupId,
        "occmDemandSignalCatalogId": args.occmDemandSignalCatalogId,
    }, opts);
}

/**
 * A collection of arguments for invoking getInternalOccmDemandSignalCatalogResources.
 */
export interface GetInternalOccmDemandSignalCatalogResourcesArgs {
    /**
     * The ocid of the compartment or tenancy in which resources are to be listed. This will also be used for authorization purposes.
     */
    compartmentId: string;
    /**
     * A query parameter to filter the list of demand signal catalog resources based on the namespace.
     */
    demandSignalNamespace?: string;
    filters?: inputs.CapacityManagement.GetInternalOccmDemandSignalCatalogResourcesFilter[];
    /**
     * A query parameter to filter the list of demand signal catalog resource based on the resource name.
     */
    name?: string;
    /**
     * The customer group ocid by which we would filter the list.
     */
    occCustomerGroupId: string;
    /**
     * The ocid of demand signal catalog id.
     */
    occmDemandSignalCatalogId: string;
}

/**
 * A collection of values returned by getInternalOccmDemandSignalCatalogResources.
 */
export interface GetInternalOccmDemandSignalCatalogResourcesResult {
    /**
     * The OCID of the tenancy from which the request to create the demand signal catalog was made.
     */
    readonly compartmentId: string;
    readonly demandSignalNamespace?: string;
    readonly filters?: outputs.CapacityManagement.GetInternalOccmDemandSignalCatalogResourcesFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The list of internal_occm_demand_signal_catalog_resource_collection.
     */
    readonly internalOccmDemandSignalCatalogResourceCollections: outputs.CapacityManagement.GetInternalOccmDemandSignalCatalogResourcesInternalOccmDemandSignalCatalogResourceCollection[];
    /**
     * The name of the Oracle Cloud Infrastructure resource that you want to request.
     */
    readonly name?: string;
    /**
     * The OCID of the customerGroup.
     */
    readonly occCustomerGroupId: string;
    /**
     * This OCID of the demand signal catalog
     */
    readonly occmDemandSignalCatalogId: string;
}
/**
 * This data source provides the list of Internal Occm Demand Signal Catalog Resources in Oracle Cloud Infrastructure Capacity Management service.
 *
 * This API will list all the  resources across all demand signal catalogs for a given namespace and customer group.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testInternalOccmDemandSignalCatalogResources = oci.CapacityManagement.getInternalOccmDemandSignalCatalogResources({
 *     compartmentId: compartmentId,
 *     occCustomerGroupId: testOccCustomerGroup.id,
 *     occmDemandSignalCatalogId: testCatalog.id,
 *     demandSignalNamespace: internalOccmDemandSignalCatalogResourceDemandSignalNamespace,
 *     name: internalOccmDemandSignalCatalogResourceName,
 * });
 * ```
 */
export function getInternalOccmDemandSignalCatalogResourcesOutput(args: GetInternalOccmDemandSignalCatalogResourcesOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetInternalOccmDemandSignalCatalogResourcesResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:CapacityManagement/getInternalOccmDemandSignalCatalogResources:getInternalOccmDemandSignalCatalogResources", {
        "compartmentId": args.compartmentId,
        "demandSignalNamespace": args.demandSignalNamespace,
        "filters": args.filters,
        "name": args.name,
        "occCustomerGroupId": args.occCustomerGroupId,
        "occmDemandSignalCatalogId": args.occmDemandSignalCatalogId,
    }, opts);
}

/**
 * A collection of arguments for invoking getInternalOccmDemandSignalCatalogResources.
 */
export interface GetInternalOccmDemandSignalCatalogResourcesOutputArgs {
    /**
     * The ocid of the compartment or tenancy in which resources are to be listed. This will also be used for authorization purposes.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * A query parameter to filter the list of demand signal catalog resources based on the namespace.
     */
    demandSignalNamespace?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.CapacityManagement.GetInternalOccmDemandSignalCatalogResourcesFilterArgs>[]>;
    /**
     * A query parameter to filter the list of demand signal catalog resource based on the resource name.
     */
    name?: pulumi.Input<string>;
    /**
     * The customer group ocid by which we would filter the list.
     */
    occCustomerGroupId: pulumi.Input<string>;
    /**
     * The ocid of demand signal catalog id.
     */
    occmDemandSignalCatalogId: pulumi.Input<string>;
}
