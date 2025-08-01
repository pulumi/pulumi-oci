// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This resource provides the Platform Configuration resource in Oracle Cloud Infrastructure Fleet Apps Management service.
 *
 * Creates a new PlatformConfiguration.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testPlatformConfiguration = new oci.fleetappsmanagement.PlatformConfiguration("test_platform_configuration", {
 *     compartmentId: compartmentId,
 *     configCategoryDetails: {
 *         configCategory: platformConfigurationConfigCategoryDetailsConfigCategory,
 *         compatibleProducts: [{
 *             displayName: platformConfigurationConfigCategoryDetailsCompatibleProductsDisplayName,
 *             id: platformConfigurationConfigCategoryDetailsCompatibleProductsId,
 *         }],
 *         components: platformConfigurationConfigCategoryDetailsComponents,
 *         credentials: [{
 *             displayName: platformConfigurationConfigCategoryDetailsCredentialsDisplayName,
 *             id: platformConfigurationConfigCategoryDetailsCredentialsId,
 *         }],
 *         instanceId: testInstance.id,
 *         instanceName: testInstance.name,
 *         patchTypes: [{
 *             displayName: platformConfigurationConfigCategoryDetailsPatchTypesDisplayName,
 *             id: platformConfigurationConfigCategoryDetailsPatchTypesId,
 *         }],
 *         products: [{
 *             displayName: platformConfigurationConfigCategoryDetailsProductsDisplayName,
 *             id: platformConfigurationConfigCategoryDetailsProductsId,
 *         }],
 *         subCategoryDetails: {
 *             subCategory: platformConfigurationConfigCategoryDetailsSubCategoryDetailsSubCategory,
 *             components: platformConfigurationConfigCategoryDetailsSubCategoryDetailsComponents,
 *             credentials: [{
 *                 displayName: platformConfigurationConfigCategoryDetailsSubCategoryDetailsCredentialsDisplayName,
 *                 id: platformConfigurationConfigCategoryDetailsSubCategoryDetailsCredentialsId,
 *             }],
 *             patchTypes: [{
 *                 displayName: platformConfigurationConfigCategoryDetailsSubCategoryDetailsPatchTypesDisplayName,
 *                 id: platformConfigurationConfigCategoryDetailsSubCategoryDetailsPatchTypesId,
 *             }],
 *             versions: platformConfigurationConfigCategoryDetailsSubCategoryDetailsVersions,
 *         },
 *         versions: platformConfigurationConfigCategoryDetailsVersions,
 *     },
 *     displayName: platformConfigurationDisplayName,
 *     description: platformConfigurationDescription,
 * });
 * ```
 *
 * ## Import
 *
 * PlatformConfigurations can be imported using the `id`, e.g.
 *
 * ```sh
 * $ pulumi import oci:FleetAppsManagement/platformConfiguration:PlatformConfiguration test_platform_configuration "id"
 * ```
 */
export class PlatformConfiguration extends pulumi.CustomResource {
    /**
     * Get an existing PlatformConfiguration resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: PlatformConfigurationState, opts?: pulumi.CustomResourceOptions): PlatformConfiguration {
        return new PlatformConfiguration(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:FleetAppsManagement/platformConfiguration:PlatformConfiguration';

    /**
     * Returns true if the given object is an instance of PlatformConfiguration.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is PlatformConfiguration {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === PlatformConfiguration.__pulumiType;
    }

    /**
     * (Updatable) Compartment OCID
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * (Updatable) Config Category Details.
     */
    public readonly configCategoryDetails!: pulumi.Output<outputs.FleetAppsManagement.PlatformConfigurationConfigCategoryDetails>;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    public /*out*/ readonly definedTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * (Updatable) A user-friendly description. To provide some insight about the resource. Avoid entering confidential information.
     */
    public readonly description!: pulumi.Output<string>;
    /**
     * (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My new resource` 
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    public /*out*/ readonly freeformTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     */
    public /*out*/ readonly lifecycleDetails!: pulumi.Output<string>;
    /**
     * Associated region
     */
    public /*out*/ readonly resourceRegion!: pulumi.Output<string>;
    /**
     * The current state of the PlatformConfiguration.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    public /*out*/ readonly systemTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * The time this resource was created. An RFC3339 formatted datetime string.
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The time this resource was last updated. An RFC3339 formatted datetime string.
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;
    /**
     * The type of the configuration.
     */
    public /*out*/ readonly type!: pulumi.Output<string>;

    /**
     * Create a PlatformConfiguration resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: PlatformConfigurationArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: PlatformConfigurationArgs | PlatformConfigurationState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as PlatformConfigurationState | undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["configCategoryDetails"] = state ? state.configCategoryDetails : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["description"] = state ? state.description : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["lifecycleDetails"] = state ? state.lifecycleDetails : undefined;
            resourceInputs["resourceRegion"] = state ? state.resourceRegion : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["systemTags"] = state ? state.systemTags : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeUpdated"] = state ? state.timeUpdated : undefined;
            resourceInputs["type"] = state ? state.type : undefined;
        } else {
            const args = argsOrState as PlatformConfigurationArgs | undefined;
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.configCategoryDetails === undefined) && !opts.urn) {
                throw new Error("Missing required property 'configCategoryDetails'");
            }
            if ((!args || args.displayName === undefined) && !opts.urn) {
                throw new Error("Missing required property 'displayName'");
            }
            resourceInputs["compartmentId"] = args ? args.compartmentId : undefined;
            resourceInputs["configCategoryDetails"] = args ? args.configCategoryDetails : undefined;
            resourceInputs["description"] = args ? args.description : undefined;
            resourceInputs["displayName"] = args ? args.displayName : undefined;
            resourceInputs["definedTags"] = undefined /*out*/;
            resourceInputs["freeformTags"] = undefined /*out*/;
            resourceInputs["lifecycleDetails"] = undefined /*out*/;
            resourceInputs["resourceRegion"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["systemTags"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeUpdated"] = undefined /*out*/;
            resourceInputs["type"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(PlatformConfiguration.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering PlatformConfiguration resources.
 */
export interface PlatformConfigurationState {
    /**
     * (Updatable) Compartment OCID
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) Config Category Details.
     */
    configCategoryDetails?: pulumi.Input<inputs.FleetAppsManagement.PlatformConfigurationConfigCategoryDetails>;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) A user-friendly description. To provide some insight about the resource. Avoid entering confidential information.
     */
    description?: pulumi.Input<string>;
    /**
     * (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My new resource` 
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    displayName?: pulumi.Input<string>;
    /**
     * Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     */
    lifecycleDetails?: pulumi.Input<string>;
    /**
     * Associated region
     */
    resourceRegion?: pulumi.Input<string>;
    /**
     * The current state of the PlatformConfiguration.
     */
    state?: pulumi.Input<string>;
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    systemTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * The time this resource was created. An RFC3339 formatted datetime string.
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The time this resource was last updated. An RFC3339 formatted datetime string.
     */
    timeUpdated?: pulumi.Input<string>;
    /**
     * The type of the configuration.
     */
    type?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a PlatformConfiguration resource.
 */
export interface PlatformConfigurationArgs {
    /**
     * (Updatable) Compartment OCID
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) Config Category Details.
     */
    configCategoryDetails: pulumi.Input<inputs.FleetAppsManagement.PlatformConfigurationConfigCategoryDetails>;
    /**
     * (Updatable) A user-friendly description. To provide some insight about the resource. Avoid entering confidential information.
     */
    description?: pulumi.Input<string>;
    /**
     * (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My new resource` 
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    displayName: pulumi.Input<string>;
}
