// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This resource provides the Application Vip resource in Oracle Cloud Infrastructure Database service.
 *
 * Creates a new application virtual IP (VIP) address in the specified cloud VM cluster based on the request parameters you provide.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testApplicationVip = new oci.database.ApplicationVip("test_application_vip", {
 *     cloudVmClusterId: testCloudVmCluster.id,
 *     hostnameLabel: applicationVipHostnameLabel,
 *     subnetId: testSubnet.id,
 *     dbNodeId: testDbNode.id,
 *     ipAddress: applicationVipIpAddress,
 *     ipv6address: applicationVipIpv6address,
 * });
 * ```
 *
 * ## Import
 *
 * ApplicationVips can be imported using the `id`, e.g.
 *
 * ```sh
 * $ pulumi import oci:Database/applicationVip:ApplicationVip test_application_vip "id"
 * ```
 */
export class ApplicationVip extends pulumi.CustomResource {
    /**
     * Get an existing ApplicationVip resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: ApplicationVipState, opts?: pulumi.CustomResourceOptions): ApplicationVip {
        return new ApplicationVip(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:Database/applicationVip:ApplicationVip';

    /**
     * Returns true if the given object is an instance of ApplicationVip.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is ApplicationVip {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === ApplicationVip.__pulumiType;
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cloud VM cluster associated with the application virtual IP (VIP) address.
     */
    public readonly cloudVmClusterId!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    public /*out*/ readonly compartmentId!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DB node associated with the application virtual IP (VIP) address.
     */
    public readonly dbNodeId!: pulumi.Output<string>;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     */
    public /*out*/ readonly definedTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    public /*out*/ readonly freeformTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * The hostname of the application virtual IP (VIP) address.
     */
    public readonly hostnameLabel!: pulumi.Output<string>;
    /**
     * The application virtual IP (VIP) IPv4 address.
     */
    public readonly ipAddress!: pulumi.Output<string>;
    /**
     * The application virtual IP (VIP) IPv6 address.
     */
    public readonly ipv6address!: pulumi.Output<string>;
    /**
     * Additional information about the current lifecycle state of the application virtual IP (VIP) address.
     */
    public /*out*/ readonly lifecycleDetails!: pulumi.Output<string>;
    /**
     * The current lifecycle state of the application virtual IP (VIP) address.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet associated with the application virtual IP (VIP) address.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    public readonly subnetId!: pulumi.Output<string>;
    /**
     * The date and time when the create operation for the application virtual IP (VIP) address completed.
     */
    public /*out*/ readonly timeAssigned!: pulumi.Output<string>;

    /**
     * Create a ApplicationVip resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: ApplicationVipArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: ApplicationVipArgs | ApplicationVipState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as ApplicationVipState | undefined;
            resourceInputs["cloudVmClusterId"] = state ? state.cloudVmClusterId : undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["dbNodeId"] = state ? state.dbNodeId : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["hostnameLabel"] = state ? state.hostnameLabel : undefined;
            resourceInputs["ipAddress"] = state ? state.ipAddress : undefined;
            resourceInputs["ipv6address"] = state ? state.ipv6address : undefined;
            resourceInputs["lifecycleDetails"] = state ? state.lifecycleDetails : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["subnetId"] = state ? state.subnetId : undefined;
            resourceInputs["timeAssigned"] = state ? state.timeAssigned : undefined;
        } else {
            const args = argsOrState as ApplicationVipArgs | undefined;
            if ((!args || args.cloudVmClusterId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'cloudVmClusterId'");
            }
            if ((!args || args.hostnameLabel === undefined) && !opts.urn) {
                throw new Error("Missing required property 'hostnameLabel'");
            }
            if ((!args || args.subnetId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'subnetId'");
            }
            resourceInputs["cloudVmClusterId"] = args ? args.cloudVmClusterId : undefined;
            resourceInputs["dbNodeId"] = args ? args.dbNodeId : undefined;
            resourceInputs["hostnameLabel"] = args ? args.hostnameLabel : undefined;
            resourceInputs["ipAddress"] = args ? args.ipAddress : undefined;
            resourceInputs["ipv6address"] = args ? args.ipv6address : undefined;
            resourceInputs["subnetId"] = args ? args.subnetId : undefined;
            resourceInputs["compartmentId"] = undefined /*out*/;
            resourceInputs["definedTags"] = undefined /*out*/;
            resourceInputs["freeformTags"] = undefined /*out*/;
            resourceInputs["lifecycleDetails"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["timeAssigned"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(ApplicationVip.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering ApplicationVip resources.
 */
export interface ApplicationVipState {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cloud VM cluster associated with the application virtual IP (VIP) address.
     */
    cloudVmClusterId?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DB node associated with the application virtual IP (VIP) address.
     */
    dbNodeId?: pulumi.Input<string>;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * The hostname of the application virtual IP (VIP) address.
     */
    hostnameLabel?: pulumi.Input<string>;
    /**
     * The application virtual IP (VIP) IPv4 address.
     */
    ipAddress?: pulumi.Input<string>;
    /**
     * The application virtual IP (VIP) IPv6 address.
     */
    ipv6address?: pulumi.Input<string>;
    /**
     * Additional information about the current lifecycle state of the application virtual IP (VIP) address.
     */
    lifecycleDetails?: pulumi.Input<string>;
    /**
     * The current lifecycle state of the application virtual IP (VIP) address.
     */
    state?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet associated with the application virtual IP (VIP) address.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    subnetId?: pulumi.Input<string>;
    /**
     * The date and time when the create operation for the application virtual IP (VIP) address completed.
     */
    timeAssigned?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a ApplicationVip resource.
 */
export interface ApplicationVipArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cloud VM cluster associated with the application virtual IP (VIP) address.
     */
    cloudVmClusterId: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DB node associated with the application virtual IP (VIP) address.
     */
    dbNodeId?: pulumi.Input<string>;
    /**
     * The hostname of the application virtual IP (VIP) address.
     */
    hostnameLabel: pulumi.Input<string>;
    /**
     * The application virtual IP (VIP) IPv4 address.
     */
    ipAddress?: pulumi.Input<string>;
    /**
     * The application virtual IP (VIP) IPv6 address.
     */
    ipv6address?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet associated with the application virtual IP (VIP) address.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    subnetId: pulumi.Input<string>;
}
