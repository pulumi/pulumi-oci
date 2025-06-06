// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This resource provides the Bds Instance Metastore Config resource in Oracle Cloud Infrastructure Big Data Service service.
 *
 * Create and activate external metastore configuration.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testBdsInstanceMetastoreConfig = new oci.bigdataservice.BdsInstanceMetastoreConfig("test_bds_instance_metastore_config", {
 *     bdsApiKeyId: testApiKey.id,
 *     bdsApiKeyPassphrase: bdsInstanceMetastoreConfigBdsApiKeyPassphrase,
 *     bdsInstanceId: testBdsInstance.id,
 *     clusterAdminPassword: bdsInstanceMetastoreConfigClusterAdminPassword,
 *     metastoreId: testMetastore.id,
 *     displayName: bdsInstanceMetastoreConfigDisplayName,
 * });
 * ```
 *
 * ## Import
 *
 * BdsInstanceMetastoreConfigs can be imported using the `id`, e.g.
 *
 * ```sh
 * $ pulumi import oci:BigDataService/bdsInstanceMetastoreConfig:BdsInstanceMetastoreConfig test_bds_instance_metastore_config "bdsInstances/{bdsInstanceId}/metastoreConfigs/{metastoreConfigId}"
 * ```
 */
export class BdsInstanceMetastoreConfig extends pulumi.CustomResource {
    /**
     * Get an existing BdsInstanceMetastoreConfig resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: BdsInstanceMetastoreConfigState, opts?: pulumi.CustomResourceOptions): BdsInstanceMetastoreConfig {
        return new BdsInstanceMetastoreConfig(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:BigDataService/bdsInstanceMetastoreConfig:BdsInstanceMetastoreConfig';

    /**
     * Returns true if the given object is an instance of BdsInstanceMetastoreConfig.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is BdsInstanceMetastoreConfig {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === BdsInstanceMetastoreConfig.__pulumiType;
    }

    /**
     * (Updatable) An optional integer, when flipped triggers activation of metastore config.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    public readonly activateTrigger!: pulumi.Output<number | undefined>;
    /**
     * (Updatable) The ID of BDS Api Key used for Data Catalog metastore integration.
     */
    public readonly bdsApiKeyId!: pulumi.Output<string>;
    /**
     * (Updatable) Base-64 encoded passphrase of the BDS Api Key.
     */
    public readonly bdsApiKeyPassphrase!: pulumi.Output<string>;
    /**
     * The OCID of the cluster.
     */
    public readonly bdsInstanceId!: pulumi.Output<string>;
    /**
     * (Updatable) Base-64 encoded password for the cluster admin user.
     */
    public readonly clusterAdminPassword!: pulumi.Output<string>;
    /**
     * (Updatable) The display name of the metastore configuration
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * The OCID of the Data Catalog metastore.
     */
    public readonly metastoreId!: pulumi.Output<string>;
    /**
     * The type of the metastore in the metastore configuration.
     */
    public /*out*/ readonly metastoreType!: pulumi.Output<string>;
    /**
     * the lifecycle state of the metastore configuration.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * The time when the configuration was created, shown as an RFC 3339 formatted datetime string.
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The time when the configuration was updated, shown as an RFC 3339 formatted datetime string.
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;

    /**
     * Create a BdsInstanceMetastoreConfig resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: BdsInstanceMetastoreConfigArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: BdsInstanceMetastoreConfigArgs | BdsInstanceMetastoreConfigState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as BdsInstanceMetastoreConfigState | undefined;
            resourceInputs["activateTrigger"] = state ? state.activateTrigger : undefined;
            resourceInputs["bdsApiKeyId"] = state ? state.bdsApiKeyId : undefined;
            resourceInputs["bdsApiKeyPassphrase"] = state ? state.bdsApiKeyPassphrase : undefined;
            resourceInputs["bdsInstanceId"] = state ? state.bdsInstanceId : undefined;
            resourceInputs["clusterAdminPassword"] = state ? state.clusterAdminPassword : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["metastoreId"] = state ? state.metastoreId : undefined;
            resourceInputs["metastoreType"] = state ? state.metastoreType : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeUpdated"] = state ? state.timeUpdated : undefined;
        } else {
            const args = argsOrState as BdsInstanceMetastoreConfigArgs | undefined;
            if ((!args || args.bdsApiKeyId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'bdsApiKeyId'");
            }
            if ((!args || args.bdsApiKeyPassphrase === undefined) && !opts.urn) {
                throw new Error("Missing required property 'bdsApiKeyPassphrase'");
            }
            if ((!args || args.bdsInstanceId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'bdsInstanceId'");
            }
            if ((!args || args.clusterAdminPassword === undefined) && !opts.urn) {
                throw new Error("Missing required property 'clusterAdminPassword'");
            }
            if ((!args || args.metastoreId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'metastoreId'");
            }
            resourceInputs["activateTrigger"] = args ? args.activateTrigger : undefined;
            resourceInputs["bdsApiKeyId"] = args ? args.bdsApiKeyId : undefined;
            resourceInputs["bdsApiKeyPassphrase"] = args?.bdsApiKeyPassphrase ? pulumi.secret(args.bdsApiKeyPassphrase) : undefined;
            resourceInputs["bdsInstanceId"] = args ? args.bdsInstanceId : undefined;
            resourceInputs["clusterAdminPassword"] = args?.clusterAdminPassword ? pulumi.secret(args.clusterAdminPassword) : undefined;
            resourceInputs["displayName"] = args ? args.displayName : undefined;
            resourceInputs["metastoreId"] = args ? args.metastoreId : undefined;
            resourceInputs["metastoreType"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeUpdated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        const secretOpts = { additionalSecretOutputs: ["bdsApiKeyPassphrase", "clusterAdminPassword"] };
        opts = pulumi.mergeOptions(opts, secretOpts);
        super(BdsInstanceMetastoreConfig.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering BdsInstanceMetastoreConfig resources.
 */
export interface BdsInstanceMetastoreConfigState {
    /**
     * (Updatable) An optional integer, when flipped triggers activation of metastore config.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    activateTrigger?: pulumi.Input<number>;
    /**
     * (Updatable) The ID of BDS Api Key used for Data Catalog metastore integration.
     */
    bdsApiKeyId?: pulumi.Input<string>;
    /**
     * (Updatable) Base-64 encoded passphrase of the BDS Api Key.
     */
    bdsApiKeyPassphrase?: pulumi.Input<string>;
    /**
     * The OCID of the cluster.
     */
    bdsInstanceId?: pulumi.Input<string>;
    /**
     * (Updatable) Base-64 encoded password for the cluster admin user.
     */
    clusterAdminPassword?: pulumi.Input<string>;
    /**
     * (Updatable) The display name of the metastore configuration
     */
    displayName?: pulumi.Input<string>;
    /**
     * The OCID of the Data Catalog metastore.
     */
    metastoreId?: pulumi.Input<string>;
    /**
     * The type of the metastore in the metastore configuration.
     */
    metastoreType?: pulumi.Input<string>;
    /**
     * the lifecycle state of the metastore configuration.
     */
    state?: pulumi.Input<string>;
    /**
     * The time when the configuration was created, shown as an RFC 3339 formatted datetime string.
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The time when the configuration was updated, shown as an RFC 3339 formatted datetime string.
     */
    timeUpdated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a BdsInstanceMetastoreConfig resource.
 */
export interface BdsInstanceMetastoreConfigArgs {
    /**
     * (Updatable) An optional integer, when flipped triggers activation of metastore config.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    activateTrigger?: pulumi.Input<number>;
    /**
     * (Updatable) The ID of BDS Api Key used for Data Catalog metastore integration.
     */
    bdsApiKeyId: pulumi.Input<string>;
    /**
     * (Updatable) Base-64 encoded passphrase of the BDS Api Key.
     */
    bdsApiKeyPassphrase: pulumi.Input<string>;
    /**
     * The OCID of the cluster.
     */
    bdsInstanceId: pulumi.Input<string>;
    /**
     * (Updatable) Base-64 encoded password for the cluster admin user.
     */
    clusterAdminPassword: pulumi.Input<string>;
    /**
     * (Updatable) The display name of the metastore configuration
     */
    displayName?: pulumi.Input<string>;
    /**
     * The OCID of the Data Catalog metastore.
     */
    metastoreId: pulumi.Input<string>;
}
