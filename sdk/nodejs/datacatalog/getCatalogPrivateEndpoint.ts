// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Catalog Private Endpoint resource in Oracle Cloud Infrastructure Data Catalog service.
 *
 * Gets a specific private reverse connection by identifier.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testCatalogPrivateEndpoint = oci.DataCatalog.getCatalogPrivateEndpoint({
 *     catalogPrivateEndpointId: oci_datacatalog_catalog_private_endpoint.test_catalog_private_endpoint.id,
 * });
 * ```
 */
export function getCatalogPrivateEndpoint(args: GetCatalogPrivateEndpointArgs, opts?: pulumi.InvokeOptions): Promise<GetCatalogPrivateEndpointResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:DataCatalog/getCatalogPrivateEndpoint:getCatalogPrivateEndpoint", {
        "catalogPrivateEndpointId": args.catalogPrivateEndpointId,
    }, opts);
}

/**
 * A collection of arguments for invoking getCatalogPrivateEndpoint.
 */
export interface GetCatalogPrivateEndpointArgs {
    /**
     * Unique private reverse connection identifier.
     */
    catalogPrivateEndpointId: string;
}

/**
 * A collection of values returned by getCatalogPrivateEndpoint.
 */
export interface GetCatalogPrivateEndpointResult {
    /**
     * The list of catalogs using the private reverse connection endpoint
     */
    readonly attachedCatalogs: string[];
    readonly catalogPrivateEndpointId: string;
    /**
     * Identifier of the compartment this private endpoint belongs to
     */
    readonly compartmentId: string;
    /**
     * Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{"foo-namespace.bar-key": "value"}`
     */
    readonly definedTags: {[key: string]: any};
    /**
     * Mutable name of the Private Reverse Connection Endpoint
     */
    readonly displayName: string;
    /**
     * List of DNS zones to be used by the data assets to be harvested. Example: custpvtsubnet.oraclevcn.com for data asset: db.custpvtsubnet.oraclevcn.com
     */
    readonly dnsZones: string[];
    /**
     * Simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    readonly freeformTags: {[key: string]: any};
    /**
     * Unique identifier that is immutable
     */
    readonly id: string;
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in 'Failed' state.
     */
    readonly lifecycleDetails: string;
    /**
     * The current state of the private endpoint resource.
     */
    readonly state: string;
    /**
     * Subnet Identifier
     */
    readonly subnetId: string;
    /**
     * The time the private endpoint was created. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
     */
    readonly timeCreated: string;
    /**
     * The time the private endpoint was updated. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
     */
    readonly timeUpdated: string;
}

export function getCatalogPrivateEndpointOutput(args: GetCatalogPrivateEndpointOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetCatalogPrivateEndpointResult> {
    return pulumi.output(args).apply(a => getCatalogPrivateEndpoint(a, opts))
}

/**
 * A collection of arguments for invoking getCatalogPrivateEndpoint.
 */
export interface GetCatalogPrivateEndpointOutputArgs {
    /**
     * Unique private reverse connection identifier.
     */
    catalogPrivateEndpointId: pulumi.Input<string>;
}