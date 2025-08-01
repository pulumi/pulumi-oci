// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This resource provides the Provision resource in Oracle Cloud Infrastructure Fleet Apps Management service.
 *
 * Creates a Provision.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testProvision = new oci.fleetappsmanagement.Provision("test_provision", {
 *     compartmentId: compartmentId,
 *     configCatalogItemId: testCatalogItem.id,
 *     fleetId: testFleet.id,
 *     packageCatalogItemId: testCatalogItem.id,
 *     tfVariableRegionId: testRegion.id,
 *     tfVariableTenancyId: testTenancy.id,
 *     definedTags: {
 *         "foo-namespace.bar-key": "value",
 *     },
 *     displayName: provisionDisplayName,
 *     freeformTags: {
 *         "bar-key": "value",
 *     },
 *     provisionDescription: provisionProvisionDescription,
 *     tfVariableCompartmentId: testCompartment.id,
 *     tfVariableCurrentUserId: testUser.id,
 * });
 * ```
 *
 * ## Import
 *
 * Provisions can be imported using the `id`, e.g.
 *
 * ```sh
 * $ pulumi import oci:FleetAppsManagement/provision:Provision test_provision "id"
 * ```
 */
export class Provision extends pulumi.CustomResource {
    /**
     * Get an existing Provision resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: ProvisionState, opts?: pulumi.CustomResourceOptions): Provision {
        return new Provision(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:FleetAppsManagement/provision:Provision';

    /**
     * Returns true if the given object is an instance of Provision.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is Provision {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === Provision.__pulumiType;
    }

    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to create the FamProvision in.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * A display Name of the Catalog Item in the Catalog.
     */
    public /*out*/ readonly configCatalogItemDisplayName!: pulumi.Output<string>;
    /**
     * A [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Catalog Item to a file with key/value pairs to set up variables for createStack API.
     */
    public readonly configCatalogItemId!: pulumi.Output<string>;
    /**
     * A listing ID of the Catalog Item in the Catalog.
     */
    public /*out*/ readonly configCatalogItemListingId!: pulumi.Output<string>;
    /**
     * A listing version of the Catalog Item in the Catalog.
     */
    public /*out*/ readonly configCatalogItemListingVersion!: pulumi.Output<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * The deployed resources and their summary
     */
    public /*out*/ readonly deployedResources!: pulumi.Output<outputs.FleetAppsManagement.ProvisionDeployedResource[]>;
    /**
     * (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Fleet.
     */
    public readonly fleetId!: pulumi.Output<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * A message that describes the current state of the FamProvision in more detail. For example, can be used to provide actionable information for a resource in the Failed state.
     */
    public /*out*/ readonly lifecycleDetails!: pulumi.Output<string>;
    /**
     * A display Name of the Catalog Item in the Catalog.
     */
    public /*out*/ readonly packageCatalogItemDisplayName!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Catalog Item.
     */
    public readonly packageCatalogItemId!: pulumi.Output<string>;
    /**
     * A listing ID of the Catalog Item in the Catalog.
     */
    public /*out*/ readonly packageCatalogItemListingId!: pulumi.Output<string>;
    /**
     * A listing version of the Catalog Item in the Catalog.
     */
    public /*out*/ readonly packageCatalogItemListingVersion!: pulumi.Output<string>;
    /**
     * (Updatable) A description of the provision.
     */
    public readonly provisionDescription!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the RMS APPLY Job.
     */
    public /*out*/ readonly rmsApplyJobId!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the RMS Stack.
     */
    public /*out*/ readonly stackId!: pulumi.Output<string>;
    /**
     * The current state of the FamProvision.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    public /*out*/ readonly systemTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * Outputs from the pulumi up job
     */
    public /*out*/ readonly tfOutputs!: pulumi.Output<outputs.FleetAppsManagement.ProvisionTfOutput[]>;
    /**
     * An optional variable added to a list of RMS variables for createStack API. Overrides the one supplied in configuration file.
     */
    public readonly tfVariableCompartmentId!: pulumi.Output<string>;
    /**
     * An optional variable added to a list of RMS variables for createStack API. Overrides the one supplied in configuration file.
     */
    public readonly tfVariableCurrentUserId!: pulumi.Output<string>;
    /**
     * A mandatory variable added to a list of RMS variables for createStack API. Overrides the one supplied in configuration file.
     */
    public readonly tfVariableRegionId!: pulumi.Output<string>;
    /**
     * A mandatory variable added to a list of RMS variables for createStack API. Overrides the one supplied in configuration file.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    public readonly tfVariableTenancyId!: pulumi.Output<string>;
    /**
     * The date and time the FamProvision was created, in the format defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The date and time the FamProvision was updated, in the format defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;

    /**
     * Create a Provision resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: ProvisionArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: ProvisionArgs | ProvisionState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as ProvisionState | undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["configCatalogItemDisplayName"] = state ? state.configCatalogItemDisplayName : undefined;
            resourceInputs["configCatalogItemId"] = state ? state.configCatalogItemId : undefined;
            resourceInputs["configCatalogItemListingId"] = state ? state.configCatalogItemListingId : undefined;
            resourceInputs["configCatalogItemListingVersion"] = state ? state.configCatalogItemListingVersion : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["deployedResources"] = state ? state.deployedResources : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["fleetId"] = state ? state.fleetId : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["lifecycleDetails"] = state ? state.lifecycleDetails : undefined;
            resourceInputs["packageCatalogItemDisplayName"] = state ? state.packageCatalogItemDisplayName : undefined;
            resourceInputs["packageCatalogItemId"] = state ? state.packageCatalogItemId : undefined;
            resourceInputs["packageCatalogItemListingId"] = state ? state.packageCatalogItemListingId : undefined;
            resourceInputs["packageCatalogItemListingVersion"] = state ? state.packageCatalogItemListingVersion : undefined;
            resourceInputs["provisionDescription"] = state ? state.provisionDescription : undefined;
            resourceInputs["rmsApplyJobId"] = state ? state.rmsApplyJobId : undefined;
            resourceInputs["stackId"] = state ? state.stackId : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["systemTags"] = state ? state.systemTags : undefined;
            resourceInputs["tfOutputs"] = state ? state.tfOutputs : undefined;
            resourceInputs["tfVariableCompartmentId"] = state ? state.tfVariableCompartmentId : undefined;
            resourceInputs["tfVariableCurrentUserId"] = state ? state.tfVariableCurrentUserId : undefined;
            resourceInputs["tfVariableRegionId"] = state ? state.tfVariableRegionId : undefined;
            resourceInputs["tfVariableTenancyId"] = state ? state.tfVariableTenancyId : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeUpdated"] = state ? state.timeUpdated : undefined;
        } else {
            const args = argsOrState as ProvisionArgs | undefined;
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.configCatalogItemId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'configCatalogItemId'");
            }
            if ((!args || args.fleetId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'fleetId'");
            }
            if ((!args || args.packageCatalogItemId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'packageCatalogItemId'");
            }
            if ((!args || args.tfVariableRegionId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'tfVariableRegionId'");
            }
            if ((!args || args.tfVariableTenancyId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'tfVariableTenancyId'");
            }
            resourceInputs["compartmentId"] = args ? args.compartmentId : undefined;
            resourceInputs["configCatalogItemId"] = args ? args.configCatalogItemId : undefined;
            resourceInputs["definedTags"] = args ? args.definedTags : undefined;
            resourceInputs["displayName"] = args ? args.displayName : undefined;
            resourceInputs["fleetId"] = args ? args.fleetId : undefined;
            resourceInputs["freeformTags"] = args ? args.freeformTags : undefined;
            resourceInputs["packageCatalogItemId"] = args ? args.packageCatalogItemId : undefined;
            resourceInputs["provisionDescription"] = args ? args.provisionDescription : undefined;
            resourceInputs["tfVariableCompartmentId"] = args ? args.tfVariableCompartmentId : undefined;
            resourceInputs["tfVariableCurrentUserId"] = args ? args.tfVariableCurrentUserId : undefined;
            resourceInputs["tfVariableRegionId"] = args ? args.tfVariableRegionId : undefined;
            resourceInputs["tfVariableTenancyId"] = args ? args.tfVariableTenancyId : undefined;
            resourceInputs["configCatalogItemDisplayName"] = undefined /*out*/;
            resourceInputs["configCatalogItemListingId"] = undefined /*out*/;
            resourceInputs["configCatalogItemListingVersion"] = undefined /*out*/;
            resourceInputs["deployedResources"] = undefined /*out*/;
            resourceInputs["lifecycleDetails"] = undefined /*out*/;
            resourceInputs["packageCatalogItemDisplayName"] = undefined /*out*/;
            resourceInputs["packageCatalogItemListingId"] = undefined /*out*/;
            resourceInputs["packageCatalogItemListingVersion"] = undefined /*out*/;
            resourceInputs["rmsApplyJobId"] = undefined /*out*/;
            resourceInputs["stackId"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["systemTags"] = undefined /*out*/;
            resourceInputs["tfOutputs"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeUpdated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(Provision.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering Provision resources.
 */
export interface ProvisionState {
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to create the FamProvision in.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * A display Name of the Catalog Item in the Catalog.
     */
    configCatalogItemDisplayName?: pulumi.Input<string>;
    /**
     * A [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Catalog Item to a file with key/value pairs to set up variables for createStack API.
     */
    configCatalogItemId?: pulumi.Input<string>;
    /**
     * A listing ID of the Catalog Item in the Catalog.
     */
    configCatalogItemListingId?: pulumi.Input<string>;
    /**
     * A listing version of the Catalog Item in the Catalog.
     */
    configCatalogItemListingVersion?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * The deployed resources and their summary
     */
    deployedResources?: pulumi.Input<pulumi.Input<inputs.FleetAppsManagement.ProvisionDeployedResource>[]>;
    /**
     * (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
     */
    displayName?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Fleet.
     */
    fleetId?: pulumi.Input<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * A message that describes the current state of the FamProvision in more detail. For example, can be used to provide actionable information for a resource in the Failed state.
     */
    lifecycleDetails?: pulumi.Input<string>;
    /**
     * A display Name of the Catalog Item in the Catalog.
     */
    packageCatalogItemDisplayName?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Catalog Item.
     */
    packageCatalogItemId?: pulumi.Input<string>;
    /**
     * A listing ID of the Catalog Item in the Catalog.
     */
    packageCatalogItemListingId?: pulumi.Input<string>;
    /**
     * A listing version of the Catalog Item in the Catalog.
     */
    packageCatalogItemListingVersion?: pulumi.Input<string>;
    /**
     * (Updatable) A description of the provision.
     */
    provisionDescription?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the RMS APPLY Job.
     */
    rmsApplyJobId?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the RMS Stack.
     */
    stackId?: pulumi.Input<string>;
    /**
     * The current state of the FamProvision.
     */
    state?: pulumi.Input<string>;
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    systemTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * Outputs from the pulumi up job
     */
    tfOutputs?: pulumi.Input<pulumi.Input<inputs.FleetAppsManagement.ProvisionTfOutput>[]>;
    /**
     * An optional variable added to a list of RMS variables for createStack API. Overrides the one supplied in configuration file.
     */
    tfVariableCompartmentId?: pulumi.Input<string>;
    /**
     * An optional variable added to a list of RMS variables for createStack API. Overrides the one supplied in configuration file.
     */
    tfVariableCurrentUserId?: pulumi.Input<string>;
    /**
     * A mandatory variable added to a list of RMS variables for createStack API. Overrides the one supplied in configuration file.
     */
    tfVariableRegionId?: pulumi.Input<string>;
    /**
     * A mandatory variable added to a list of RMS variables for createStack API. Overrides the one supplied in configuration file.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    tfVariableTenancyId?: pulumi.Input<string>;
    /**
     * The date and time the FamProvision was created, in the format defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The date and time the FamProvision was updated, in the format defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     */
    timeUpdated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a Provision resource.
 */
export interface ProvisionArgs {
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to create the FamProvision in.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * A [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Catalog Item to a file with key/value pairs to set up variables for createStack API.
     */
    configCatalogItemId: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
     */
    displayName?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Fleet.
     */
    fleetId: pulumi.Input<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Catalog Item.
     */
    packageCatalogItemId: pulumi.Input<string>;
    /**
     * (Updatable) A description of the provision.
     */
    provisionDescription?: pulumi.Input<string>;
    /**
     * An optional variable added to a list of RMS variables for createStack API. Overrides the one supplied in configuration file.
     */
    tfVariableCompartmentId?: pulumi.Input<string>;
    /**
     * An optional variable added to a list of RMS variables for createStack API. Overrides the one supplied in configuration file.
     */
    tfVariableCurrentUserId?: pulumi.Input<string>;
    /**
     * A mandatory variable added to a list of RMS variables for createStack API. Overrides the one supplied in configuration file.
     */
    tfVariableRegionId: pulumi.Input<string>;
    /**
     * A mandatory variable added to a list of RMS variables for createStack API. Overrides the one supplied in configuration file.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    tfVariableTenancyId: pulumi.Input<string>;
}
