// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Registry Data Assets in Oracle Cloud Infrastructure Data Connectivity service.
 *
 * Retrieves a list of all data asset summaries.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testRegistryDataAssets = oci.DataConnectivity.getRegistryDataAssets({
 *     registryId: oci_data_connectivity_registry.test_registry.id,
 *     endpointIds: _var.registry_data_asset_endpoint_ids,
 *     excludeEndpointIds: _var.registry_data_asset_exclude_endpoint_ids,
 *     excludeTypes: _var.registry_data_asset_exclude_types,
 *     favoritesQueryParam: _var.registry_data_asset_favorites_query_param,
 *     fields: _var.registry_data_asset_fields,
 *     folderId: oci_data_connectivity_folder.test_folder.id,
 *     includeTypes: _var.registry_data_asset_include_types,
 *     name: _var.registry_data_asset_name,
 * });
 * ```
 */
export function getRegistryDataAssets(args: GetRegistryDataAssetsArgs, opts?: pulumi.InvokeOptions): Promise<GetRegistryDataAssetsResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:DataConnectivity/getRegistryDataAssets:getRegistryDataAssets", {
        "endpointIds": args.endpointIds,
        "excludeEndpointIds": args.excludeEndpointIds,
        "excludeTypes": args.excludeTypes,
        "favoritesQueryParam": args.favoritesQueryParam,
        "fields": args.fields,
        "filters": args.filters,
        "folderId": args.folderId,
        "includeTypes": args.includeTypes,
        "name": args.name,
        "registryId": args.registryId,
        "type": args.type,
    }, opts);
}

/**
 * A collection of arguments for invoking getRegistryDataAssets.
 */
export interface GetRegistryDataAssetsArgs {
    /**
     * Endpoint Ids used for data-plane APIs to filter or prefer specific endpoint.
     */
    endpointIds?: string[];
    /**
     * Endpoints which will be excluded while listing dataAssets
     */
    excludeEndpointIds?: string[];
    /**
     * Types which wont be listed while listing dataAsset/Connection
     */
    excludeTypes?: string[];
    /**
     * If value is FAVORITES_ONLY, then only objects marked as favorite by the requesting user will be included in result. If value is NON_FAVORITES_ONLY, then objects marked as favorites by the requesting user will be skipped. If value is ALL or if not specified, all objects, irrespective of favorites or not will be returned. Default is ALL.
     */
    favoritesQueryParam?: string;
    /**
     * Specifies the fields to get for an object.
     */
    fields?: string[];
    filters?: inputs.DataConnectivity.GetRegistryDataAssetsFilter[];
    /**
     * Unique key of the folder.
     */
    folderId?: string;
    /**
     * DataAsset type which needs to be listed while listing dataAssets
     */
    includeTypes?: string[];
    /**
     * Used to filter by the name of the object.
     */
    name?: string;
    /**
     * The registry Ocid.
     */
    registryId: string;
    /**
     * Specific DataAsset Type
     */
    type?: string;
}

/**
 * A collection of values returned by getRegistryDataAssets.
 */
export interface GetRegistryDataAssetsResult {
    /**
     * The list of data_asset_summary_collection.
     */
    readonly dataAssetSummaryCollections: outputs.DataConnectivity.GetRegistryDataAssetsDataAssetSummaryCollection[];
    readonly endpointIds?: string[];
    readonly excludeEndpointIds?: string[];
    readonly excludeTypes?: string[];
    readonly favoritesQueryParam?: string;
    readonly fields?: string[];
    readonly filters?: outputs.DataConnectivity.GetRegistryDataAssetsFilter[];
    readonly folderId?: string;
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    readonly includeTypes?: string[];
    /**
     * Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
     */
    readonly name?: string;
    readonly registryId: string;
    /**
     * Specific DataAsset Type
     */
    readonly type?: string;
}

export function getRegistryDataAssetsOutput(args: GetRegistryDataAssetsOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetRegistryDataAssetsResult> {
    return pulumi.output(args).apply(a => getRegistryDataAssets(a, opts))
}

/**
 * A collection of arguments for invoking getRegistryDataAssets.
 */
export interface GetRegistryDataAssetsOutputArgs {
    /**
     * Endpoint Ids used for data-plane APIs to filter or prefer specific endpoint.
     */
    endpointIds?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * Endpoints which will be excluded while listing dataAssets
     */
    excludeEndpointIds?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * Types which wont be listed while listing dataAsset/Connection
     */
    excludeTypes?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * If value is FAVORITES_ONLY, then only objects marked as favorite by the requesting user will be included in result. If value is NON_FAVORITES_ONLY, then objects marked as favorites by the requesting user will be skipped. If value is ALL or if not specified, all objects, irrespective of favorites or not will be returned. Default is ALL.
     */
    favoritesQueryParam?: pulumi.Input<string>;
    /**
     * Specifies the fields to get for an object.
     */
    fields?: pulumi.Input<pulumi.Input<string>[]>;
    filters?: pulumi.Input<pulumi.Input<inputs.DataConnectivity.GetRegistryDataAssetsFilterArgs>[]>;
    /**
     * Unique key of the folder.
     */
    folderId?: pulumi.Input<string>;
    /**
     * DataAsset type which needs to be listed while listing dataAssets
     */
    includeTypes?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * Used to filter by the name of the object.
     */
    name?: pulumi.Input<string>;
    /**
     * The registry Ocid.
     */
    registryId: pulumi.Input<string>;
    /**
     * Specific DataAsset Type
     */
    type?: pulumi.Input<string>;
}
