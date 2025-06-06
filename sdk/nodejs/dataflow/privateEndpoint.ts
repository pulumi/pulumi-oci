// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * ## Import
 *
 * PrivateEndpoints can be imported using the `id`, e.g.
 *
 * ```sh
 * $ pulumi import oci:DataFlow/privateEndpoint:PrivateEndpoint test_private_endpoint "id"
 * ```
 */
export class PrivateEndpoint extends pulumi.CustomResource {
    /**
     * Get an existing PrivateEndpoint resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: PrivateEndpointState, opts?: pulumi.CustomResourceOptions): PrivateEndpoint {
        return new PrivateEndpoint(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:DataFlow/privateEndpoint:PrivateEndpoint';

    /**
     * Returns true if the given object is an instance of PrivateEndpoint.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is PrivateEndpoint {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === PrivateEndpoint.__pulumiType;
    }

    /**
     * (Updatable) The OCID of a compartment.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * (Updatable) A user-friendly description. Avoid entering confidential information.
     */
    public readonly description!: pulumi.Output<string>;
    /**
     * (Updatable) A user-friendly name. It does not have to be unique. Avoid entering confidential information.
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * (Updatable) An array of DNS zone names. Example: `[ "app.examplecorp.com", "app.examplecorp2.com" ]`
     */
    public readonly dnsZones!: pulumi.Output<string[]>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * The detailed messages about the lifecycle state.
     */
    public /*out*/ readonly lifecycleDetails!: pulumi.Output<string>;
    /**
     * (Updatable) The maximum number of hosts to be accessed through the private endpoint. This value is used to calculate the relevant CIDR block and should be a multiple of 256.  If the value is not a multiple of 256, it is rounded up to the next multiple of 256. For example, 300 is rounded up to 512.
     */
    public readonly maxHostCount!: pulumi.Output<number>;
    /**
     * (Updatable) An array of network security group OCIDs.
     */
    public readonly nsgIds!: pulumi.Output<string[]>;
    /**
     * The OCID of the user who created the resource.
     */
    public /*out*/ readonly ownerPrincipalId!: pulumi.Output<string>;
    /**
     * The username of the user who created the resource.  If the username of the owner does not exist, `null` will be returned and the caller should refer to the ownerPrincipalId value instead.
     */
    public /*out*/ readonly ownerUserName!: pulumi.Output<string>;
    /**
     * (Updatable) An array of fqdn/port pairs used to create private endpoint. Each object is a simple key-value pair with FQDN as key and port number as value. [ { fqdn: "scan1.oracle.com", port: "1521"}, { fqdn: "scan2.oracle.com", port: "1521" } ]
     */
    public readonly scanDetails!: pulumi.Output<outputs.DataFlow.PrivateEndpointScanDetail[]>;
    /**
     * The current state of this private endpoint.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * The OCID of a subnet. 
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    public readonly subnetId!: pulumi.Output<string>;
    /**
     * The date and time the resource was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2018-04-03T21:10:29.600Z`
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The date and time the resource was updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2018-04-03T21:10:29.600Z`
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;

    /**
     * Create a PrivateEndpoint resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: PrivateEndpointArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: PrivateEndpointArgs | PrivateEndpointState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as PrivateEndpointState | undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["description"] = state ? state.description : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["dnsZones"] = state ? state.dnsZones : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["lifecycleDetails"] = state ? state.lifecycleDetails : undefined;
            resourceInputs["maxHostCount"] = state ? state.maxHostCount : undefined;
            resourceInputs["nsgIds"] = state ? state.nsgIds : undefined;
            resourceInputs["ownerPrincipalId"] = state ? state.ownerPrincipalId : undefined;
            resourceInputs["ownerUserName"] = state ? state.ownerUserName : undefined;
            resourceInputs["scanDetails"] = state ? state.scanDetails : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["subnetId"] = state ? state.subnetId : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeUpdated"] = state ? state.timeUpdated : undefined;
        } else {
            const args = argsOrState as PrivateEndpointArgs | undefined;
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.dnsZones === undefined) && !opts.urn) {
                throw new Error("Missing required property 'dnsZones'");
            }
            if ((!args || args.subnetId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'subnetId'");
            }
            resourceInputs["compartmentId"] = args ? args.compartmentId : undefined;
            resourceInputs["definedTags"] = args ? args.definedTags : undefined;
            resourceInputs["description"] = args ? args.description : undefined;
            resourceInputs["displayName"] = args ? args.displayName : undefined;
            resourceInputs["dnsZones"] = args ? args.dnsZones : undefined;
            resourceInputs["freeformTags"] = args ? args.freeformTags : undefined;
            resourceInputs["maxHostCount"] = args ? args.maxHostCount : undefined;
            resourceInputs["nsgIds"] = args ? args.nsgIds : undefined;
            resourceInputs["scanDetails"] = args ? args.scanDetails : undefined;
            resourceInputs["subnetId"] = args ? args.subnetId : undefined;
            resourceInputs["lifecycleDetails"] = undefined /*out*/;
            resourceInputs["ownerPrincipalId"] = undefined /*out*/;
            resourceInputs["ownerUserName"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeUpdated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(PrivateEndpoint.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering PrivateEndpoint resources.
 */
export interface PrivateEndpointState {
    /**
     * (Updatable) The OCID of a compartment.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) A user-friendly description. Avoid entering confidential information.
     */
    description?: pulumi.Input<string>;
    /**
     * (Updatable) A user-friendly name. It does not have to be unique. Avoid entering confidential information.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) An array of DNS zone names. Example: `[ "app.examplecorp.com", "app.examplecorp2.com" ]`
     */
    dnsZones?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * The detailed messages about the lifecycle state.
     */
    lifecycleDetails?: pulumi.Input<string>;
    /**
     * (Updatable) The maximum number of hosts to be accessed through the private endpoint. This value is used to calculate the relevant CIDR block and should be a multiple of 256.  If the value is not a multiple of 256, it is rounded up to the next multiple of 256. For example, 300 is rounded up to 512.
     */
    maxHostCount?: pulumi.Input<number>;
    /**
     * (Updatable) An array of network security group OCIDs.
     */
    nsgIds?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * The OCID of the user who created the resource.
     */
    ownerPrincipalId?: pulumi.Input<string>;
    /**
     * The username of the user who created the resource.  If the username of the owner does not exist, `null` will be returned and the caller should refer to the ownerPrincipalId value instead.
     */
    ownerUserName?: pulumi.Input<string>;
    /**
     * (Updatable) An array of fqdn/port pairs used to create private endpoint. Each object is a simple key-value pair with FQDN as key and port number as value. [ { fqdn: "scan1.oracle.com", port: "1521"}, { fqdn: "scan2.oracle.com", port: "1521" } ]
     */
    scanDetails?: pulumi.Input<pulumi.Input<inputs.DataFlow.PrivateEndpointScanDetail>[]>;
    /**
     * The current state of this private endpoint.
     */
    state?: pulumi.Input<string>;
    /**
     * The OCID of a subnet. 
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    subnetId?: pulumi.Input<string>;
    /**
     * The date and time the resource was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2018-04-03T21:10:29.600Z`
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The date and time the resource was updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2018-04-03T21:10:29.600Z`
     */
    timeUpdated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a PrivateEndpoint resource.
 */
export interface PrivateEndpointArgs {
    /**
     * (Updatable) The OCID of a compartment.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) A user-friendly description. Avoid entering confidential information.
     */
    description?: pulumi.Input<string>;
    /**
     * (Updatable) A user-friendly name. It does not have to be unique. Avoid entering confidential information.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) An array of DNS zone names. Example: `[ "app.examplecorp.com", "app.examplecorp2.com" ]`
     */
    dnsZones: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) The maximum number of hosts to be accessed through the private endpoint. This value is used to calculate the relevant CIDR block and should be a multiple of 256.  If the value is not a multiple of 256, it is rounded up to the next multiple of 256. For example, 300 is rounded up to 512.
     */
    maxHostCount?: pulumi.Input<number>;
    /**
     * (Updatable) An array of network security group OCIDs.
     */
    nsgIds?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * (Updatable) An array of fqdn/port pairs used to create private endpoint. Each object is a simple key-value pair with FQDN as key and port number as value. [ { fqdn: "scan1.oracle.com", port: "1521"}, { fqdn: "scan2.oracle.com", port: "1521" } ]
     */
    scanDetails?: pulumi.Input<pulumi.Input<inputs.DataFlow.PrivateEndpointScanDetail>[]>;
    /**
     * The OCID of a subnet. 
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    subnetId: pulumi.Input<string>;
}
