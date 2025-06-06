// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This resource provides the Data Asset resource in Oracle Cloud Infrastructure Data Catalog service.
 *
 * Create a new data asset.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDataAsset = new oci.datacatalog.DataAsset("test_data_asset", {
 *     catalogId: testCatalog.id,
 *     displayName: dataAssetDisplayName,
 *     typeKey: dataAssetTypeKey,
 *     description: dataAssetDescription,
 *     properties: dataAssetProperties,
 * });
 * ```
 *
 * ## Import
 *
 * DataAssets can be imported using the `id`, e.g.
 *
 * ```sh
 * $ pulumi import oci:DataCatalog/dataAsset:DataAsset test_data_asset "catalogs/{catalogId}/dataAssets/{dataAssetKey}"
 * ```
 */
export class DataAsset extends pulumi.CustomResource {
    /**
     * Get an existing DataAsset resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: DataAssetState, opts?: pulumi.CustomResourceOptions): DataAsset {
        return new DataAsset(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:DataCatalog/dataAsset:DataAsset';

    /**
     * Returns true if the given object is an instance of DataAsset.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is DataAsset {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === DataAsset.__pulumiType;
    }

    /**
     * Unique catalog identifier.
     */
    public readonly catalogId!: pulumi.Output<string>;
    /**
     * OCID of the user who created the data asset.
     */
    public /*out*/ readonly createdById!: pulumi.Output<string>;
    /**
     * (Updatable) Detailed description of the data asset.
     */
    public readonly description!: pulumi.Output<string>;
    /**
     * (Updatable) A user-friendly display name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * External URI that can be used to reference the object. Format will differ based on the type of object.
     */
    public /*out*/ readonly externalKey!: pulumi.Output<string>;
    /**
     * Unique data asset key that is immutable.
     */
    public /*out*/ readonly key!: pulumi.Output<string>;
    /**
     * A message describing the current state in more detail. An object not in ACTIVE state may have functional limitations, see service documentation for details.
     */
    public /*out*/ readonly lifecycleDetails!: pulumi.Output<string>;
    public readonly properties!: pulumi.Output<{[key: string]: string}>;
    /**
     * The current state of the data asset.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * The date and time the data asset was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2019-03-25T21:10:29.600Z`
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The last time that a harvest was performed on the data asset. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
     */
    public /*out*/ readonly timeHarvested!: pulumi.Output<string>;
    /**
     * The last time that any change was made to the data asset. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;
    /**
     * The key of the data asset type. This can be obtained via the '/types' endpoint.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    public readonly typeKey!: pulumi.Output<string>;
    /**
     * OCID of the user who last modified the data asset.
     */
    public /*out*/ readonly updatedById!: pulumi.Output<string>;
    /**
     * URI to the data asset instance in the API.
     */
    public /*out*/ readonly uri!: pulumi.Output<string>;

    /**
     * Create a DataAsset resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: DataAssetArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: DataAssetArgs | DataAssetState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as DataAssetState | undefined;
            resourceInputs["catalogId"] = state ? state.catalogId : undefined;
            resourceInputs["createdById"] = state ? state.createdById : undefined;
            resourceInputs["description"] = state ? state.description : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["externalKey"] = state ? state.externalKey : undefined;
            resourceInputs["key"] = state ? state.key : undefined;
            resourceInputs["lifecycleDetails"] = state ? state.lifecycleDetails : undefined;
            resourceInputs["properties"] = state ? state.properties : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeHarvested"] = state ? state.timeHarvested : undefined;
            resourceInputs["timeUpdated"] = state ? state.timeUpdated : undefined;
            resourceInputs["typeKey"] = state ? state.typeKey : undefined;
            resourceInputs["updatedById"] = state ? state.updatedById : undefined;
            resourceInputs["uri"] = state ? state.uri : undefined;
        } else {
            const args = argsOrState as DataAssetArgs | undefined;
            if ((!args || args.catalogId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'catalogId'");
            }
            if ((!args || args.displayName === undefined) && !opts.urn) {
                throw new Error("Missing required property 'displayName'");
            }
            if ((!args || args.typeKey === undefined) && !opts.urn) {
                throw new Error("Missing required property 'typeKey'");
            }
            resourceInputs["catalogId"] = args ? args.catalogId : undefined;
            resourceInputs["description"] = args ? args.description : undefined;
            resourceInputs["displayName"] = args ? args.displayName : undefined;
            resourceInputs["properties"] = args ? args.properties : undefined;
            resourceInputs["typeKey"] = args ? args.typeKey : undefined;
            resourceInputs["createdById"] = undefined /*out*/;
            resourceInputs["externalKey"] = undefined /*out*/;
            resourceInputs["key"] = undefined /*out*/;
            resourceInputs["lifecycleDetails"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeHarvested"] = undefined /*out*/;
            resourceInputs["timeUpdated"] = undefined /*out*/;
            resourceInputs["updatedById"] = undefined /*out*/;
            resourceInputs["uri"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(DataAsset.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering DataAsset resources.
 */
export interface DataAssetState {
    /**
     * Unique catalog identifier.
     */
    catalogId?: pulumi.Input<string>;
    /**
     * OCID of the user who created the data asset.
     */
    createdById?: pulumi.Input<string>;
    /**
     * (Updatable) Detailed description of the data asset.
     */
    description?: pulumi.Input<string>;
    /**
     * (Updatable) A user-friendly display name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
     */
    displayName?: pulumi.Input<string>;
    /**
     * External URI that can be used to reference the object. Format will differ based on the type of object.
     */
    externalKey?: pulumi.Input<string>;
    /**
     * Unique data asset key that is immutable.
     */
    key?: pulumi.Input<string>;
    /**
     * A message describing the current state in more detail. An object not in ACTIVE state may have functional limitations, see service documentation for details.
     */
    lifecycleDetails?: pulumi.Input<string>;
    properties?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * The current state of the data asset.
     */
    state?: pulumi.Input<string>;
    /**
     * The date and time the data asset was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2019-03-25T21:10:29.600Z`
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The last time that a harvest was performed on the data asset. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
     */
    timeHarvested?: pulumi.Input<string>;
    /**
     * The last time that any change was made to the data asset. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
     */
    timeUpdated?: pulumi.Input<string>;
    /**
     * The key of the data asset type. This can be obtained via the '/types' endpoint.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    typeKey?: pulumi.Input<string>;
    /**
     * OCID of the user who last modified the data asset.
     */
    updatedById?: pulumi.Input<string>;
    /**
     * URI to the data asset instance in the API.
     */
    uri?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a DataAsset resource.
 */
export interface DataAssetArgs {
    /**
     * Unique catalog identifier.
     */
    catalogId: pulumi.Input<string>;
    /**
     * (Updatable) Detailed description of the data asset.
     */
    description?: pulumi.Input<string>;
    /**
     * (Updatable) A user-friendly display name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
     */
    displayName: pulumi.Input<string>;
    properties?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * The key of the data asset type. This can be obtained via the '/types' endpoint.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    typeKey: pulumi.Input<string>;
}
