// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

export class VirtualNetwork extends pulumi.CustomResource {
    /**
     * Get an existing VirtualNetwork resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: VirtualNetworkState, opts?: pulumi.CustomResourceOptions): VirtualNetwork {
        return new VirtualNetwork(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:Core/virtualNetwork:VirtualNetwork';

    /**
     * Returns true if the given object is an instance of VirtualNetwork.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is VirtualNetwork {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === VirtualNetwork.__pulumiType;
    }

    public /*out*/ readonly byoipv6cidrBlocks!: pulumi.Output<string[]>;
    public readonly byoipv6cidrDetails!: pulumi.Output<outputs.Core.VirtualNetworkByoipv6cidrDetail[]>;
    public readonly cidrBlock!: pulumi.Output<string>;
    public readonly cidrBlocks!: pulumi.Output<string[]>;
    public readonly compartmentId!: pulumi.Output<string>;
    public /*out*/ readonly defaultDhcpOptionsId!: pulumi.Output<string>;
    public /*out*/ readonly defaultRouteTableId!: pulumi.Output<string>;
    public /*out*/ readonly defaultSecurityListId!: pulumi.Output<string>;
    public readonly definedTags!: pulumi.Output<{[key: string]: string}>;
    public readonly displayName!: pulumi.Output<string>;
    public readonly dnsLabel!: pulumi.Output<string>;
    public readonly freeformTags!: pulumi.Output<{[key: string]: string}>;
    public /*out*/ readonly ipv6cidrBlocks!: pulumi.Output<string[]>;
    public readonly ipv6privateCidrBlocks!: pulumi.Output<string[]>;
    public readonly isIpv6enabled!: pulumi.Output<boolean>;
    public readonly isOracleGuaAllocationEnabled!: pulumi.Output<boolean>;
    public readonly securityAttributes!: pulumi.Output<{[key: string]: string}>;
    public /*out*/ readonly state!: pulumi.Output<string>;
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    public /*out*/ readonly vcnDomainName!: pulumi.Output<string>;

    /**
     * Create a VirtualNetwork resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: VirtualNetworkArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: VirtualNetworkArgs | VirtualNetworkState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as VirtualNetworkState | undefined;
            resourceInputs["byoipv6cidrBlocks"] = state ? state.byoipv6cidrBlocks : undefined;
            resourceInputs["byoipv6cidrDetails"] = state ? state.byoipv6cidrDetails : undefined;
            resourceInputs["cidrBlock"] = state ? state.cidrBlock : undefined;
            resourceInputs["cidrBlocks"] = state ? state.cidrBlocks : undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["defaultDhcpOptionsId"] = state ? state.defaultDhcpOptionsId : undefined;
            resourceInputs["defaultRouteTableId"] = state ? state.defaultRouteTableId : undefined;
            resourceInputs["defaultSecurityListId"] = state ? state.defaultSecurityListId : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["dnsLabel"] = state ? state.dnsLabel : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["ipv6cidrBlocks"] = state ? state.ipv6cidrBlocks : undefined;
            resourceInputs["ipv6privateCidrBlocks"] = state ? state.ipv6privateCidrBlocks : undefined;
            resourceInputs["isIpv6enabled"] = state ? state.isIpv6enabled : undefined;
            resourceInputs["isOracleGuaAllocationEnabled"] = state ? state.isOracleGuaAllocationEnabled : undefined;
            resourceInputs["securityAttributes"] = state ? state.securityAttributes : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["vcnDomainName"] = state ? state.vcnDomainName : undefined;
        } else {
            const args = argsOrState as VirtualNetworkArgs | undefined;
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            resourceInputs["byoipv6cidrDetails"] = args ? args.byoipv6cidrDetails : undefined;
            resourceInputs["cidrBlock"] = args ? args.cidrBlock : undefined;
            resourceInputs["cidrBlocks"] = args ? args.cidrBlocks : undefined;
            resourceInputs["compartmentId"] = args ? args.compartmentId : undefined;
            resourceInputs["definedTags"] = args ? args.definedTags : undefined;
            resourceInputs["displayName"] = args ? args.displayName : undefined;
            resourceInputs["dnsLabel"] = args ? args.dnsLabel : undefined;
            resourceInputs["freeformTags"] = args ? args.freeformTags : undefined;
            resourceInputs["ipv6privateCidrBlocks"] = args ? args.ipv6privateCidrBlocks : undefined;
            resourceInputs["isIpv6enabled"] = args ? args.isIpv6enabled : undefined;
            resourceInputs["isOracleGuaAllocationEnabled"] = args ? args.isOracleGuaAllocationEnabled : undefined;
            resourceInputs["securityAttributes"] = args ? args.securityAttributes : undefined;
            resourceInputs["byoipv6cidrBlocks"] = undefined /*out*/;
            resourceInputs["defaultDhcpOptionsId"] = undefined /*out*/;
            resourceInputs["defaultRouteTableId"] = undefined /*out*/;
            resourceInputs["defaultSecurityListId"] = undefined /*out*/;
            resourceInputs["ipv6cidrBlocks"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["vcnDomainName"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(VirtualNetwork.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering VirtualNetwork resources.
 */
export interface VirtualNetworkState {
    byoipv6cidrBlocks?: pulumi.Input<pulumi.Input<string>[]>;
    byoipv6cidrDetails?: pulumi.Input<pulumi.Input<inputs.Core.VirtualNetworkByoipv6cidrDetail>[]>;
    cidrBlock?: pulumi.Input<string>;
    cidrBlocks?: pulumi.Input<pulumi.Input<string>[]>;
    compartmentId?: pulumi.Input<string>;
    defaultDhcpOptionsId?: pulumi.Input<string>;
    defaultRouteTableId?: pulumi.Input<string>;
    defaultSecurityListId?: pulumi.Input<string>;
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    displayName?: pulumi.Input<string>;
    dnsLabel?: pulumi.Input<string>;
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    ipv6cidrBlocks?: pulumi.Input<pulumi.Input<string>[]>;
    ipv6privateCidrBlocks?: pulumi.Input<pulumi.Input<string>[]>;
    isIpv6enabled?: pulumi.Input<boolean>;
    isOracleGuaAllocationEnabled?: pulumi.Input<boolean>;
    securityAttributes?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    state?: pulumi.Input<string>;
    timeCreated?: pulumi.Input<string>;
    vcnDomainName?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a VirtualNetwork resource.
 */
export interface VirtualNetworkArgs {
    byoipv6cidrDetails?: pulumi.Input<pulumi.Input<inputs.Core.VirtualNetworkByoipv6cidrDetail>[]>;
    cidrBlock?: pulumi.Input<string>;
    cidrBlocks?: pulumi.Input<pulumi.Input<string>[]>;
    compartmentId: pulumi.Input<string>;
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    displayName?: pulumi.Input<string>;
    dnsLabel?: pulumi.Input<string>;
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    ipv6privateCidrBlocks?: pulumi.Input<pulumi.Input<string>[]>;
    isIpv6enabled?: pulumi.Input<boolean>;
    isOracleGuaAllocationEnabled?: pulumi.Input<boolean>;
    securityAttributes?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
}
