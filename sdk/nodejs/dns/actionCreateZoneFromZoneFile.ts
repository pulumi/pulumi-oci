// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This resource provides the Action Create Zone From Zone File resource in Oracle Cloud Infrastructure DNS service.
 *
 * Creates a new zone from a zone file in the specified compartment.
 *
 * After the zone has been created, it should be further managed by importing it to an `oci.Dns.Zone` resource.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testActionCreateZoneFromZoneFile = new oci.dns.ActionCreateZoneFromZoneFile("testActionCreateZoneFromZoneFile", {
 *     createZoneFromZoneFileDetails: _var.action_create_zone_from_zone_file_create_zone_from_zone_file_details,
 *     compartmentId: _var.compartment_id,
 *     scope: _var.action_create_zone_from_zone_file_scope,
 *     viewId: oci_dns_view.test_view.id,
 * });
 * ```
 *
 * ## Import
 *
 * ActionCreateZoneFromZoneFile can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:Dns/actionCreateZoneFromZoneFile:ActionCreateZoneFromZoneFile test_action_create_zone_from_zone_file "id"
 * ```
 */
export class ActionCreateZoneFromZoneFile extends pulumi.CustomResource {
    /**
     * Get an existing ActionCreateZoneFromZoneFile resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: ActionCreateZoneFromZoneFileState, opts?: pulumi.CustomResourceOptions): ActionCreateZoneFromZoneFile {
        return new ActionCreateZoneFromZoneFile(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:Dns/actionCreateZoneFromZoneFile:ActionCreateZoneFromZoneFile';

    /**
     * Returns true if the given object is an instance of ActionCreateZoneFromZoneFile.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is ActionCreateZoneFromZoneFile {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === ActionCreateZoneFromZoneFile.__pulumiType;
    }

    /**
     * The OCID of the compartment the resource belongs to.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * The zone file contents.
     */
    public readonly createZoneFromZoneFileDetails!: pulumi.Output<string>;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     */
    public /*out*/ readonly definedTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * External secondary servers for the zone. This field is currently not supported when `zoneType` is `SECONDARY` or `scope` is `PRIVATE`.
     */
    public /*out*/ readonly externalDownstreams!: pulumi.Output<outputs.Dns.ActionCreateZoneFromZoneFileExternalDownstream[]>;
    /**
     * External master servers for the zone. `externalMasters` becomes a required parameter when the `zoneType` value is `SECONDARY`.
     */
    public /*out*/ readonly externalMasters!: pulumi.Output<outputs.Dns.ActionCreateZoneFromZoneFileExternalMaster[]>;
    /**
     * Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     */
    public /*out*/ readonly freeformTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * A Boolean flag indicating whether or not parts of the resource are unable to be explicitly managed.
     */
    public /*out*/ readonly isProtected!: pulumi.Output<boolean>;
    /**
     * The name of the zone.
     */
    public /*out*/ readonly name!: pulumi.Output<string>;
    /**
     * The authoritative nameservers for the zone.
     */
    public /*out*/ readonly nameservers!: pulumi.Output<outputs.Dns.ActionCreateZoneFromZoneFileNameserver[]>;
    /**
     * Specifies to operate only on resources that have a matching DNS scope.
     */
    public readonly scope!: pulumi.Output<string>;
    /**
     * The canonical absolute URL of the resource.
     */
    public /*out*/ readonly self!: pulumi.Output<string>;
    /**
     * The current serial of the zone. As seen in the zone's SOA record.
     */
    public /*out*/ readonly serial!: pulumi.Output<string>;
    /**
     * The current state of the zone resource.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * The date and time the resource was created in "YYYY-MM-ddThh:mm:ssZ" format with a Z offset, as defined by RFC 3339.
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * Version is the never-repeating, totally-orderable, version of the zone, from which the serial field of the zone's SOA record is derived.
     */
    public /*out*/ readonly version!: pulumi.Output<string>;
    /**
     * The OCID of the view the resource is associated with.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    public readonly viewId!: pulumi.Output<string>;
    /**
     * The Oracle Cloud Infrastructure nameservers that transfer the zone data with external nameservers.
     */
    public /*out*/ readonly zoneTransferServers!: pulumi.Output<outputs.Dns.ActionCreateZoneFromZoneFileZoneTransferServer[]>;
    /**
     * The type of the zone. Must be either `PRIMARY` or `SECONDARY`. `SECONDARY` is only supported for GLOBAL zones.
     */
    public /*out*/ readonly zoneType!: pulumi.Output<string>;

    /**
     * Create a ActionCreateZoneFromZoneFile resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: ActionCreateZoneFromZoneFileArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: ActionCreateZoneFromZoneFileArgs | ActionCreateZoneFromZoneFileState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as ActionCreateZoneFromZoneFileState | undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["createZoneFromZoneFileDetails"] = state ? state.createZoneFromZoneFileDetails : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["externalDownstreams"] = state ? state.externalDownstreams : undefined;
            resourceInputs["externalMasters"] = state ? state.externalMasters : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["isProtected"] = state ? state.isProtected : undefined;
            resourceInputs["name"] = state ? state.name : undefined;
            resourceInputs["nameservers"] = state ? state.nameservers : undefined;
            resourceInputs["scope"] = state ? state.scope : undefined;
            resourceInputs["self"] = state ? state.self : undefined;
            resourceInputs["serial"] = state ? state.serial : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["version"] = state ? state.version : undefined;
            resourceInputs["viewId"] = state ? state.viewId : undefined;
            resourceInputs["zoneTransferServers"] = state ? state.zoneTransferServers : undefined;
            resourceInputs["zoneType"] = state ? state.zoneType : undefined;
        } else {
            const args = argsOrState as ActionCreateZoneFromZoneFileArgs | undefined;
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.createZoneFromZoneFileDetails === undefined) && !opts.urn) {
                throw new Error("Missing required property 'createZoneFromZoneFileDetails'");
            }
            resourceInputs["compartmentId"] = args ? args.compartmentId : undefined;
            resourceInputs["createZoneFromZoneFileDetails"] = args ? args.createZoneFromZoneFileDetails : undefined;
            resourceInputs["scope"] = args ? args.scope : undefined;
            resourceInputs["viewId"] = args ? args.viewId : undefined;
            resourceInputs["definedTags"] = undefined /*out*/;
            resourceInputs["externalDownstreams"] = undefined /*out*/;
            resourceInputs["externalMasters"] = undefined /*out*/;
            resourceInputs["freeformTags"] = undefined /*out*/;
            resourceInputs["isProtected"] = undefined /*out*/;
            resourceInputs["name"] = undefined /*out*/;
            resourceInputs["nameservers"] = undefined /*out*/;
            resourceInputs["self"] = undefined /*out*/;
            resourceInputs["serial"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["version"] = undefined /*out*/;
            resourceInputs["zoneTransferServers"] = undefined /*out*/;
            resourceInputs["zoneType"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(ActionCreateZoneFromZoneFile.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering ActionCreateZoneFromZoneFile resources.
 */
export interface ActionCreateZoneFromZoneFileState {
    /**
     * The OCID of the compartment the resource belongs to.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * The zone file contents.
     */
    createZoneFromZoneFileDetails?: pulumi.Input<string>;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * External secondary servers for the zone. This field is currently not supported when `zoneType` is `SECONDARY` or `scope` is `PRIVATE`.
     */
    externalDownstreams?: pulumi.Input<pulumi.Input<inputs.Dns.ActionCreateZoneFromZoneFileExternalDownstream>[]>;
    /**
     * External master servers for the zone. `externalMasters` becomes a required parameter when the `zoneType` value is `SECONDARY`.
     */
    externalMasters?: pulumi.Input<pulumi.Input<inputs.Dns.ActionCreateZoneFromZoneFileExternalMaster>[]>;
    /**
     * Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * A Boolean flag indicating whether or not parts of the resource are unable to be explicitly managed.
     */
    isProtected?: pulumi.Input<boolean>;
    /**
     * The name of the zone.
     */
    name?: pulumi.Input<string>;
    /**
     * The authoritative nameservers for the zone.
     */
    nameservers?: pulumi.Input<pulumi.Input<inputs.Dns.ActionCreateZoneFromZoneFileNameserver>[]>;
    /**
     * Specifies to operate only on resources that have a matching DNS scope.
     */
    scope?: pulumi.Input<string>;
    /**
     * The canonical absolute URL of the resource.
     */
    self?: pulumi.Input<string>;
    /**
     * The current serial of the zone. As seen in the zone's SOA record.
     */
    serial?: pulumi.Input<string>;
    /**
     * The current state of the zone resource.
     */
    state?: pulumi.Input<string>;
    /**
     * The date and time the resource was created in "YYYY-MM-ddThh:mm:ssZ" format with a Z offset, as defined by RFC 3339.
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * Version is the never-repeating, totally-orderable, version of the zone, from which the serial field of the zone's SOA record is derived.
     */
    version?: pulumi.Input<string>;
    /**
     * The OCID of the view the resource is associated with.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    viewId?: pulumi.Input<string>;
    /**
     * The Oracle Cloud Infrastructure nameservers that transfer the zone data with external nameservers.
     */
    zoneTransferServers?: pulumi.Input<pulumi.Input<inputs.Dns.ActionCreateZoneFromZoneFileZoneTransferServer>[]>;
    /**
     * The type of the zone. Must be either `PRIMARY` or `SECONDARY`. `SECONDARY` is only supported for GLOBAL zones.
     */
    zoneType?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a ActionCreateZoneFromZoneFile resource.
 */
export interface ActionCreateZoneFromZoneFileArgs {
    /**
     * The OCID of the compartment the resource belongs to.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * The zone file contents.
     */
    createZoneFromZoneFileDetails: pulumi.Input<string>;
    /**
     * Specifies to operate only on resources that have a matching DNS scope.
     */
    scope?: pulumi.Input<string>;
    /**
     * The OCID of the view the resource is associated with.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    viewId?: pulumi.Input<string>;
}