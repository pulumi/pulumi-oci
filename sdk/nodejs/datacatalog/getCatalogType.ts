// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Catalog Type resource in Oracle Cloud Infrastructure Data Catalog service.
 *
 * Gets a specific type by key within a data catalog.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testCatalogType = oci.DataCatalog.getCatalogType({
 *     catalogId: testCatalog.id,
 *     typeKey: catalogTypeTypeKey,
 *     fields: catalogTypeFields,
 * });
 * ```
 */
export function getCatalogType(args: GetCatalogTypeArgs, opts?: pulumi.InvokeOptions): Promise<GetCatalogTypeResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:DataCatalog/getCatalogType:getCatalogType", {
        "catalogId": args.catalogId,
        "fields": args.fields,
        "typeKey": args.typeKey,
    }, opts);
}

/**
 * A collection of arguments for invoking getCatalogType.
 */
export interface GetCatalogTypeArgs {
    /**
     * Unique catalog identifier.
     */
    catalogId: string;
    /**
     * Specifies the fields to return in a type response.
     */
    fields?: string[];
    /**
     * Unique type key.
     */
    typeKey: string;
}

/**
 * A collection of values returned by getCatalogType.
 */
export interface GetCatalogTypeResult {
    /**
     * The data catalog's OCID.
     */
    readonly catalogId: string;
    /**
     * Detailed description of the type.
     */
    readonly description: string;
    /**
     * Mapping type equivalence in the external system.
     */
    readonly externalTypeName: string;
    readonly fields?: string[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * Indicates whether the type is approved for use as a classifying object.
     */
    readonly isApproved: boolean;
    /**
     * Indicates whether the type is internal, making it unavailable for use by metadata elements.
     */
    readonly isInternal: boolean;
    /**
     * Indicates whether the type can be used for tagging metadata elements.
     */
    readonly isTag: boolean;
    /**
     * Unique type key that is immutable.
     */
    readonly key: string;
    /**
     * The immutable name of the type.
     */
    readonly name: string;
    /**
     * A map of arrays which defines the type specific properties, both required and optional. The map keys are category names and the values are arrays contiaing all property details. Every property is contained inside of a category. Most types have required properties within the "default" category. Example: `{ "properties": { "default": { "attributes:": [ { "name": "host", "type": "string", "isRequired": true, "isUpdatable": false }, ... ] } } }`
     */
    readonly properties: {[key: string]: string};
    /**
     * The current state of the type.
     */
    readonly state: string;
    /**
     * Indicates the category this type belongs to. For instance, data assets, connections.
     */
    readonly typeCategory: string;
    readonly typeKey: string;
    /**
     * URI to the type instance in the API.
     */
    readonly uri: string;
}
/**
 * This data source provides details about a specific Catalog Type resource in Oracle Cloud Infrastructure Data Catalog service.
 *
 * Gets a specific type by key within a data catalog.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testCatalogType = oci.DataCatalog.getCatalogType({
 *     catalogId: testCatalog.id,
 *     typeKey: catalogTypeTypeKey,
 *     fields: catalogTypeFields,
 * });
 * ```
 */
export function getCatalogTypeOutput(args: GetCatalogTypeOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetCatalogTypeResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:DataCatalog/getCatalogType:getCatalogType", {
        "catalogId": args.catalogId,
        "fields": args.fields,
        "typeKey": args.typeKey,
    }, opts);
}

/**
 * A collection of arguments for invoking getCatalogType.
 */
export interface GetCatalogTypeOutputArgs {
    /**
     * Unique catalog identifier.
     */
    catalogId: pulumi.Input<string>;
    /**
     * Specifies the fields to return in a type response.
     */
    fields?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * Unique type key.
     */
    typeKey: pulumi.Input<string>;
}
