// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This resource provides the Enterprise Manager Bridge resource in Oracle Cloud Infrastructure Opsi service.
 *
 * Create a Enterprise Manager bridge in Operations Insights.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testEnterpriseManagerBridge = new oci.opsi.EnterpriseManagerBridge("test_enterprise_manager_bridge", {
 *     compartmentId: compartmentId,
 *     displayName: enterpriseManagerBridgeDisplayName,
 *     objectStorageBucketName: testBucket.name,
 *     definedTags: {
 *         "foo-namespace.bar-key": "value",
 *     },
 *     description: enterpriseManagerBridgeDescription,
 *     freeformTags: {
 *         "bar-key": "value",
 *     },
 * });
 * ```
 *
 * ## Import
 *
 * EnterpriseManagerBridges can be imported using the `id`, e.g.
 *
 * ```sh
 * $ pulumi import oci:Opsi/enterpriseManagerBridge:EnterpriseManagerBridge test_enterprise_manager_bridge "id"
 * ```
 */
export class EnterpriseManagerBridge extends pulumi.CustomResource {
    /**
     * Get an existing EnterpriseManagerBridge resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: EnterpriseManagerBridgeState, opts?: pulumi.CustomResourceOptions): EnterpriseManagerBridge {
        return new EnterpriseManagerBridge(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:Opsi/enterpriseManagerBridge:EnterpriseManagerBridge';

    /**
     * Returns true if the given object is an instance of EnterpriseManagerBridge.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is EnterpriseManagerBridge {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === EnterpriseManagerBridge.__pulumiType;
    }

    /**
     * (Updatable) Compartment identifier of the Enterprise Manager bridge
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * (Updatable) Description of Enterprise Manager Bridge
     */
    public readonly description!: pulumi.Output<string>;
    /**
     * (Updatable) User-friedly name of Enterprise Manager Bridge that does not have to be unique.
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     */
    public /*out*/ readonly lifecycleDetails!: pulumi.Output<string>;
    /**
     * Object Storage Bucket Name
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    public readonly objectStorageBucketName!: pulumi.Output<string>;
    /**
     * A message describing status of the object storage bucket of this resource. For example, it can be used to provide actionable information about the permission and content validity of the bucket.
     */
    public /*out*/ readonly objectStorageBucketStatusDetails!: pulumi.Output<string>;
    /**
     * Object Storage Namespace Name
     */
    public /*out*/ readonly objectStorageNamespaceName!: pulumi.Output<string>;
    /**
     * The current state of the Enterprise Manager bridge.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    public /*out*/ readonly systemTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * The time the the Enterprise Manager bridge was first created. An RFC3339 formatted datetime string
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The time the Enterprise Manager bridge was updated. An RFC3339 formatted datetime string
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;

    /**
     * Create a EnterpriseManagerBridge resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: EnterpriseManagerBridgeArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: EnterpriseManagerBridgeArgs | EnterpriseManagerBridgeState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as EnterpriseManagerBridgeState | undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["description"] = state ? state.description : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["lifecycleDetails"] = state ? state.lifecycleDetails : undefined;
            resourceInputs["objectStorageBucketName"] = state ? state.objectStorageBucketName : undefined;
            resourceInputs["objectStorageBucketStatusDetails"] = state ? state.objectStorageBucketStatusDetails : undefined;
            resourceInputs["objectStorageNamespaceName"] = state ? state.objectStorageNamespaceName : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["systemTags"] = state ? state.systemTags : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeUpdated"] = state ? state.timeUpdated : undefined;
        } else {
            const args = argsOrState as EnterpriseManagerBridgeArgs | undefined;
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.displayName === undefined) && !opts.urn) {
                throw new Error("Missing required property 'displayName'");
            }
            if ((!args || args.objectStorageBucketName === undefined) && !opts.urn) {
                throw new Error("Missing required property 'objectStorageBucketName'");
            }
            resourceInputs["compartmentId"] = args ? args.compartmentId : undefined;
            resourceInputs["definedTags"] = args ? args.definedTags : undefined;
            resourceInputs["description"] = args ? args.description : undefined;
            resourceInputs["displayName"] = args ? args.displayName : undefined;
            resourceInputs["freeformTags"] = args ? args.freeformTags : undefined;
            resourceInputs["objectStorageBucketName"] = args ? args.objectStorageBucketName : undefined;
            resourceInputs["lifecycleDetails"] = undefined /*out*/;
            resourceInputs["objectStorageBucketStatusDetails"] = undefined /*out*/;
            resourceInputs["objectStorageNamespaceName"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["systemTags"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeUpdated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(EnterpriseManagerBridge.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering EnterpriseManagerBridge resources.
 */
export interface EnterpriseManagerBridgeState {
    /**
     * (Updatable) Compartment identifier of the Enterprise Manager bridge
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) Description of Enterprise Manager Bridge
     */
    description?: pulumi.Input<string>;
    /**
     * (Updatable) User-friedly name of Enterprise Manager Bridge that does not have to be unique.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     */
    lifecycleDetails?: pulumi.Input<string>;
    /**
     * Object Storage Bucket Name
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    objectStorageBucketName?: pulumi.Input<string>;
    /**
     * A message describing status of the object storage bucket of this resource. For example, it can be used to provide actionable information about the permission and content validity of the bucket.
     */
    objectStorageBucketStatusDetails?: pulumi.Input<string>;
    /**
     * Object Storage Namespace Name
     */
    objectStorageNamespaceName?: pulumi.Input<string>;
    /**
     * The current state of the Enterprise Manager bridge.
     */
    state?: pulumi.Input<string>;
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    systemTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * The time the the Enterprise Manager bridge was first created. An RFC3339 formatted datetime string
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The time the Enterprise Manager bridge was updated. An RFC3339 formatted datetime string
     */
    timeUpdated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a EnterpriseManagerBridge resource.
 */
export interface EnterpriseManagerBridgeArgs {
    /**
     * (Updatable) Compartment identifier of the Enterprise Manager bridge
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) Description of Enterprise Manager Bridge
     */
    description?: pulumi.Input<string>;
    /**
     * (Updatable) User-friedly name of Enterprise Manager Bridge that does not have to be unique.
     */
    displayName: pulumi.Input<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * Object Storage Bucket Name
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    objectStorageBucketName: pulumi.Input<string>;
}
