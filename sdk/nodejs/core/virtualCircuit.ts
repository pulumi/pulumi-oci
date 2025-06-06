// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This resource provides the Virtual Circuit resource in Oracle Cloud Infrastructure Core service.
 *
 * Creates a new virtual circuit to use with Oracle Cloud
 * Infrastructure FastConnect. For more information, see
 * [FastConnect Overview](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/fastconnect.htm).
 *
 * For the purposes of access control, you must provide the OCID of the
 * compartment where you want the virtual circuit to reside. If you're
 * not sure which compartment to use, put the virtual circuit in the
 * same compartment with the DRG it's using. For more information about
 * compartments and access control, see
 * [Overview of the IAM Service](https://docs.cloud.oracle.com/iaas/Content/Identity/Concepts/overview.htm).
 * For information about OCIDs, see
 * [Resource Identifiers](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
 *
 * You may optionally specify a *display name* for the virtual circuit.
 * It does not have to be unique, and you can change it. Avoid entering confidential information.
 *
 * **Important:** When creating a virtual circuit, you specify a DRG for
 * the traffic to flow through. Make sure you attach the DRG to your
 * VCN and confirm the VCN's routing sends traffic to the DRG. Otherwise
 * traffic will not flow. For more information, see
 * [Route Tables](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/managingroutetables.htm).
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testVirtualCircuit = new oci.core.VirtualCircuit("test_virtual_circuit", {
 *     compartmentId: compartmentId,
 *     type: virtualCircuitType,
 *     bandwidthShapeName: virtualCircuitBandwidthShapeName,
 *     bgpAdminState: virtualCircuitBgpAdminState,
 *     crossConnectMappings: [{
 *         bgpMd5authKey: virtualCircuitCrossConnectMappingsBgpMd5authKey,
 *         crossConnectOrCrossConnectGroupId: testCrossConnectOrCrossConnectGroup.id,
 *         customerBgpPeeringIp: virtualCircuitCrossConnectMappingsCustomerBgpPeeringIp,
 *         customerBgpPeeringIpv6: virtualCircuitCrossConnectMappingsCustomerBgpPeeringIpv6,
 *         oracleBgpPeeringIp: virtualCircuitCrossConnectMappingsOracleBgpPeeringIp,
 *         oracleBgpPeeringIpv6: virtualCircuitCrossConnectMappingsOracleBgpPeeringIpv6,
 *         vlan: virtualCircuitCrossConnectMappingsVlan,
 *     }],
 *     customerAsn: virtualCircuitCustomerAsn,
 *     customerBgpAsn: virtualCircuitCustomerBgpAsn,
 *     definedTags: {
 *         "Operations.CostCenter": "42",
 *     },
 *     displayName: virtualCircuitDisplayName,
 *     freeformTags: {
 *         Department: "Finance",
 *     },
 *     ipMtu: virtualCircuitIpMtu,
 *     isBfdEnabled: virtualCircuitIsBfdEnabled,
 *     isTransportMode: virtualCircuitIsTransportMode,
 *     gatewayId: testGateway.id,
 *     providerServiceId: testFastConnectProviderServices.fastConnectProviderServices[0].id,
 *     providerServiceKeyName: virtualCircuitProviderServiceKeyName,
 *     publicPrefixes: [{
 *         cidrBlock: virtualCircuitPublicPrefixesCidrBlock,
 *     }],
 *     region: virtualCircuitRegion,
 *     routingPolicies: virtualCircuitRoutingPolicy,
 * });
 * ```
 *
 * ## Import
 *
 * VirtualCircuits can be imported using the `id`, e.g.
 *
 * ```sh
 * $ pulumi import oci:Core/virtualCircuit:VirtualCircuit test_virtual_circuit "id"
 * ```
 */
export class VirtualCircuit extends pulumi.CustomResource {
    /**
     * Get an existing VirtualCircuit resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: VirtualCircuitState, opts?: pulumi.CustomResourceOptions): VirtualCircuit {
        return new VirtualCircuit(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:Core/virtualCircuit:VirtualCircuit';

    /**
     * Returns true if the given object is an instance of VirtualCircuit.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is VirtualCircuit {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === VirtualCircuit.__pulumiType;
    }

    /**
     * (Updatable) The provisioned data rate of the connection. To get a list of the available bandwidth levels (that is, shapes), see [ListFastConnectProviderServiceVirtualCircuitBandwidthShapes](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/FastConnectProviderService/ListFastConnectProviderVirtualCircuitBandwidthShapes).  Example: `10 Gbps`
     */
    public readonly bandwidthShapeName!: pulumi.Output<string>;
    /**
     * (Updatable) Set to `ENABLED` (the default) to activate the BGP session of the virtual circuit, set to `DISABLED` to deactivate the virtual circuit.
     */
    public readonly bgpAdminState!: pulumi.Output<string>;
    /**
     * The state of the Ipv6 BGP session associated with the virtual circuit.
     */
    public /*out*/ readonly bgpIpv6sessionState!: pulumi.Output<string>;
    /**
     * Deprecated. Instead use the information in [FastConnectProviderService](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/FastConnectProviderService/).
     *
     * @deprecated The 'bgp_management' field has been deprecated. Please use the 'oci_core_fast_connect_provider_service' data source instead.
     */
    public /*out*/ readonly bgpManagement!: pulumi.Output<string>;
    /**
     * The state of the Ipv4 BGP session associated with the virtual circuit.
     */
    public /*out*/ readonly bgpSessionState!: pulumi.Output<string>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to contain the virtual circuit.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * (Updatable) Create a `CrossConnectMapping` for each cross-connect or cross-connect group this virtual circuit will run on.
     */
    public readonly crossConnectMappings!: pulumi.Output<outputs.Core.VirtualCircuitCrossConnectMapping[]>;
    /**
     * (Updatable) Your BGP ASN (either public or private). Provide this value only if there's a BGP session that goes from your edge router to Oracle. Otherwise, leave this empty or null. Can be a 2-byte or 4-byte ASN. Uses "asplain" format.  Example: `12345` (2-byte) or `1587232876` (4-byte)
     */
    public readonly customerAsn!: pulumi.Output<string>;
    /**
     * (Updatable) Deprecated. Instead use `customerAsn`. If you specify values for both, the request will be rejected.
     *
     * @deprecated The 'customer_bgp_asn' field has been deprecated. Please use 'customer_asn' instead.
     */
    public readonly customerBgpAsn!: pulumi.Output<number>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * (Updatable) For private virtual circuits only. The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the [dynamic routing gateway (DRG)](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Drg) that this virtual circuit uses.
     */
    public readonly gatewayId!: pulumi.Output<string>;
    /**
     * (Updatable) The layer 3 IP MTU to use with this virtual circuit.
     */
    public readonly ipMtu!: pulumi.Output<string>;
    /**
     * (Updatable) Set to `true` to enable BFD for IPv4 BGP peering, or set to `false` to disable BFD. If this is not set, the default is `false`.
     */
    public readonly isBfdEnabled!: pulumi.Output<boolean>;
    /**
     * (Updatable) Set to `true` for the virtual circuit to carry only encrypted traffic, or set to `false` for the virtual circuit to carry unencrypted traffic. If this is not set, the default is `false`.
     */
    public readonly isTransportMode!: pulumi.Output<boolean>;
    /**
     * The Oracle BGP ASN.
     */
    public /*out*/ readonly oracleBgpAsn!: pulumi.Output<number>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the service offered by the provider (if you're connecting via a provider). To get a list of the available service offerings, see [ListFastConnectProviderServices](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/FastConnectProviderService/ListFastConnectProviderServices).
     */
    public readonly providerServiceId!: pulumi.Output<string>;
    /**
     * (Updatable) The service key name offered by the provider (if the customer is connecting via a provider).
     */
    public readonly providerServiceKeyName!: pulumi.Output<string>;
    /**
     * The provider's state in relation to this virtual circuit (if the customer is connecting via a provider). ACTIVE means the provider has provisioned the virtual circuit from their end. INACTIVE means the provider has not yet provisioned the virtual circuit, or has de-provisioned it.
     */
    public /*out*/ readonly providerState!: pulumi.Output<string>;
    /**
     * (Updatable) For a public virtual circuit. The public IP prefixes (CIDRs) the customer wants to advertise across the connection.
     */
    public readonly publicPrefixes!: pulumi.Output<outputs.Core.VirtualCircuitPublicPrefix[] | undefined>;
    /**
     * Provider-supplied reference information about this virtual circuit (if the customer is connecting via a provider).
     */
    public /*out*/ readonly referenceComment!: pulumi.Output<string>;
    /**
     * The Oracle Cloud Infrastructure region where this virtual circuit is located. Example: `phx`
     */
    public readonly region!: pulumi.Output<string>;
    /**
     * (Updatable) The routing policy sets how routing information about the Oracle cloud is shared over a public virtual circuit. Policies available are: `ORACLE_SERVICE_NETWORK`, `REGIONAL`, `MARKET_LEVEL`, and `GLOBAL`. See [Route Filtering](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/routingonprem.htm#route_filtering) for details. By default, routing information is shared for all routes in the same market.
     */
    public readonly routingPolicies!: pulumi.Output<string[]>;
    /**
     * Provider service type.
     */
    public /*out*/ readonly serviceType!: pulumi.Output<string>;
    /**
     * The virtual circuit's current state. For information about the different states, see [FastConnect Overview](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/fastconnect.htm).
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * The date and time the virtual circuit was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The type of IP addresses used in this virtual circuit. PRIVATE means [RFC 1918](https://tools.ietf.org/html/rfc1918) addresses (10.0.0.0/8, 172.16/12, and 192.168/16). 
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    public readonly type!: pulumi.Output<string>;
    /**
     * This resource provides redundancy level details for the virtual circuit. For more about redundancy, see [FastConnect Redundancy Best Practices](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/fastconnectresiliency.htm).
     */
    public /*out*/ readonly virtualCircuitRedundancyMetadatas!: pulumi.Output<outputs.Core.VirtualCircuitVirtualCircuitRedundancyMetadata[]>;

    /**
     * Create a VirtualCircuit resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: VirtualCircuitArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: VirtualCircuitArgs | VirtualCircuitState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as VirtualCircuitState | undefined;
            resourceInputs["bandwidthShapeName"] = state ? state.bandwidthShapeName : undefined;
            resourceInputs["bgpAdminState"] = state ? state.bgpAdminState : undefined;
            resourceInputs["bgpIpv6sessionState"] = state ? state.bgpIpv6sessionState : undefined;
            resourceInputs["bgpManagement"] = state ? state.bgpManagement : undefined;
            resourceInputs["bgpSessionState"] = state ? state.bgpSessionState : undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["crossConnectMappings"] = state ? state.crossConnectMappings : undefined;
            resourceInputs["customerAsn"] = state ? state.customerAsn : undefined;
            resourceInputs["customerBgpAsn"] = state ? state.customerBgpAsn : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["gatewayId"] = state ? state.gatewayId : undefined;
            resourceInputs["ipMtu"] = state ? state.ipMtu : undefined;
            resourceInputs["isBfdEnabled"] = state ? state.isBfdEnabled : undefined;
            resourceInputs["isTransportMode"] = state ? state.isTransportMode : undefined;
            resourceInputs["oracleBgpAsn"] = state ? state.oracleBgpAsn : undefined;
            resourceInputs["providerServiceId"] = state ? state.providerServiceId : undefined;
            resourceInputs["providerServiceKeyName"] = state ? state.providerServiceKeyName : undefined;
            resourceInputs["providerState"] = state ? state.providerState : undefined;
            resourceInputs["publicPrefixes"] = state ? state.publicPrefixes : undefined;
            resourceInputs["referenceComment"] = state ? state.referenceComment : undefined;
            resourceInputs["region"] = state ? state.region : undefined;
            resourceInputs["routingPolicies"] = state ? state.routingPolicies : undefined;
            resourceInputs["serviceType"] = state ? state.serviceType : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["type"] = state ? state.type : undefined;
            resourceInputs["virtualCircuitRedundancyMetadatas"] = state ? state.virtualCircuitRedundancyMetadatas : undefined;
        } else {
            const args = argsOrState as VirtualCircuitArgs | undefined;
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.type === undefined) && !opts.urn) {
                throw new Error("Missing required property 'type'");
            }
            resourceInputs["bandwidthShapeName"] = args ? args.bandwidthShapeName : undefined;
            resourceInputs["bgpAdminState"] = args ? args.bgpAdminState : undefined;
            resourceInputs["compartmentId"] = args ? args.compartmentId : undefined;
            resourceInputs["crossConnectMappings"] = args ? args.crossConnectMappings : undefined;
            resourceInputs["customerAsn"] = args ? args.customerAsn : undefined;
            resourceInputs["customerBgpAsn"] = args ? args.customerBgpAsn : undefined;
            resourceInputs["definedTags"] = args ? args.definedTags : undefined;
            resourceInputs["displayName"] = args ? args.displayName : undefined;
            resourceInputs["freeformTags"] = args ? args.freeformTags : undefined;
            resourceInputs["gatewayId"] = args ? args.gatewayId : undefined;
            resourceInputs["ipMtu"] = args ? args.ipMtu : undefined;
            resourceInputs["isBfdEnabled"] = args ? args.isBfdEnabled : undefined;
            resourceInputs["isTransportMode"] = args ? args.isTransportMode : undefined;
            resourceInputs["providerServiceId"] = args ? args.providerServiceId : undefined;
            resourceInputs["providerServiceKeyName"] = args ? args.providerServiceKeyName : undefined;
            resourceInputs["publicPrefixes"] = args ? args.publicPrefixes : undefined;
            resourceInputs["region"] = args ? args.region : undefined;
            resourceInputs["routingPolicies"] = args ? args.routingPolicies : undefined;
            resourceInputs["type"] = args ? args.type : undefined;
            resourceInputs["bgpIpv6sessionState"] = undefined /*out*/;
            resourceInputs["bgpManagement"] = undefined /*out*/;
            resourceInputs["bgpSessionState"] = undefined /*out*/;
            resourceInputs["oracleBgpAsn"] = undefined /*out*/;
            resourceInputs["providerState"] = undefined /*out*/;
            resourceInputs["referenceComment"] = undefined /*out*/;
            resourceInputs["serviceType"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["virtualCircuitRedundancyMetadatas"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(VirtualCircuit.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering VirtualCircuit resources.
 */
export interface VirtualCircuitState {
    /**
     * (Updatable) The provisioned data rate of the connection. To get a list of the available bandwidth levels (that is, shapes), see [ListFastConnectProviderServiceVirtualCircuitBandwidthShapes](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/FastConnectProviderService/ListFastConnectProviderVirtualCircuitBandwidthShapes).  Example: `10 Gbps`
     */
    bandwidthShapeName?: pulumi.Input<string>;
    /**
     * (Updatable) Set to `ENABLED` (the default) to activate the BGP session of the virtual circuit, set to `DISABLED` to deactivate the virtual circuit.
     */
    bgpAdminState?: pulumi.Input<string>;
    /**
     * The state of the Ipv6 BGP session associated with the virtual circuit.
     */
    bgpIpv6sessionState?: pulumi.Input<string>;
    /**
     * Deprecated. Instead use the information in [FastConnectProviderService](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/FastConnectProviderService/).
     *
     * @deprecated The 'bgp_management' field has been deprecated. Please use the 'oci_core_fast_connect_provider_service' data source instead.
     */
    bgpManagement?: pulumi.Input<string>;
    /**
     * The state of the Ipv4 BGP session associated with the virtual circuit.
     */
    bgpSessionState?: pulumi.Input<string>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to contain the virtual circuit.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) Create a `CrossConnectMapping` for each cross-connect or cross-connect group this virtual circuit will run on.
     */
    crossConnectMappings?: pulumi.Input<pulumi.Input<inputs.Core.VirtualCircuitCrossConnectMapping>[]>;
    /**
     * (Updatable) Your BGP ASN (either public or private). Provide this value only if there's a BGP session that goes from your edge router to Oracle. Otherwise, leave this empty or null. Can be a 2-byte or 4-byte ASN. Uses "asplain" format.  Example: `12345` (2-byte) or `1587232876` (4-byte)
     */
    customerAsn?: pulumi.Input<string>;
    /**
     * (Updatable) Deprecated. Instead use `customerAsn`. If you specify values for both, the request will be rejected.
     *
     * @deprecated The 'customer_bgp_asn' field has been deprecated. Please use 'customer_asn' instead.
     */
    customerBgpAsn?: pulumi.Input<number>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) For private virtual circuits only. The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the [dynamic routing gateway (DRG)](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Drg) that this virtual circuit uses.
     */
    gatewayId?: pulumi.Input<string>;
    /**
     * (Updatable) The layer 3 IP MTU to use with this virtual circuit.
     */
    ipMtu?: pulumi.Input<string>;
    /**
     * (Updatable) Set to `true` to enable BFD for IPv4 BGP peering, or set to `false` to disable BFD. If this is not set, the default is `false`.
     */
    isBfdEnabled?: pulumi.Input<boolean>;
    /**
     * (Updatable) Set to `true` for the virtual circuit to carry only encrypted traffic, or set to `false` for the virtual circuit to carry unencrypted traffic. If this is not set, the default is `false`.
     */
    isTransportMode?: pulumi.Input<boolean>;
    /**
     * The Oracle BGP ASN.
     */
    oracleBgpAsn?: pulumi.Input<number>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the service offered by the provider (if you're connecting via a provider). To get a list of the available service offerings, see [ListFastConnectProviderServices](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/FastConnectProviderService/ListFastConnectProviderServices).
     */
    providerServiceId?: pulumi.Input<string>;
    /**
     * (Updatable) The service key name offered by the provider (if the customer is connecting via a provider).
     */
    providerServiceKeyName?: pulumi.Input<string>;
    /**
     * The provider's state in relation to this virtual circuit (if the customer is connecting via a provider). ACTIVE means the provider has provisioned the virtual circuit from their end. INACTIVE means the provider has not yet provisioned the virtual circuit, or has de-provisioned it.
     */
    providerState?: pulumi.Input<string>;
    /**
     * (Updatable) For a public virtual circuit. The public IP prefixes (CIDRs) the customer wants to advertise across the connection.
     */
    publicPrefixes?: pulumi.Input<pulumi.Input<inputs.Core.VirtualCircuitPublicPrefix>[]>;
    /**
     * Provider-supplied reference information about this virtual circuit (if the customer is connecting via a provider).
     */
    referenceComment?: pulumi.Input<string>;
    /**
     * The Oracle Cloud Infrastructure region where this virtual circuit is located. Example: `phx`
     */
    region?: pulumi.Input<string>;
    /**
     * (Updatable) The routing policy sets how routing information about the Oracle cloud is shared over a public virtual circuit. Policies available are: `ORACLE_SERVICE_NETWORK`, `REGIONAL`, `MARKET_LEVEL`, and `GLOBAL`. See [Route Filtering](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/routingonprem.htm#route_filtering) for details. By default, routing information is shared for all routes in the same market.
     */
    routingPolicies?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * Provider service type.
     */
    serviceType?: pulumi.Input<string>;
    /**
     * The virtual circuit's current state. For information about the different states, see [FastConnect Overview](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/fastconnect.htm).
     */
    state?: pulumi.Input<string>;
    /**
     * The date and time the virtual circuit was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The type of IP addresses used in this virtual circuit. PRIVATE means [RFC 1918](https://tools.ietf.org/html/rfc1918) addresses (10.0.0.0/8, 172.16/12, and 192.168/16). 
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    type?: pulumi.Input<string>;
    /**
     * This resource provides redundancy level details for the virtual circuit. For more about redundancy, see [FastConnect Redundancy Best Practices](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/fastconnectresiliency.htm).
     */
    virtualCircuitRedundancyMetadatas?: pulumi.Input<pulumi.Input<inputs.Core.VirtualCircuitVirtualCircuitRedundancyMetadata>[]>;
}

/**
 * The set of arguments for constructing a VirtualCircuit resource.
 */
export interface VirtualCircuitArgs {
    /**
     * (Updatable) The provisioned data rate of the connection. To get a list of the available bandwidth levels (that is, shapes), see [ListFastConnectProviderServiceVirtualCircuitBandwidthShapes](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/FastConnectProviderService/ListFastConnectProviderVirtualCircuitBandwidthShapes).  Example: `10 Gbps`
     */
    bandwidthShapeName?: pulumi.Input<string>;
    /**
     * (Updatable) Set to `ENABLED` (the default) to activate the BGP session of the virtual circuit, set to `DISABLED` to deactivate the virtual circuit.
     */
    bgpAdminState?: pulumi.Input<string>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to contain the virtual circuit.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) Create a `CrossConnectMapping` for each cross-connect or cross-connect group this virtual circuit will run on.
     */
    crossConnectMappings?: pulumi.Input<pulumi.Input<inputs.Core.VirtualCircuitCrossConnectMapping>[]>;
    /**
     * (Updatable) Your BGP ASN (either public or private). Provide this value only if there's a BGP session that goes from your edge router to Oracle. Otherwise, leave this empty or null. Can be a 2-byte or 4-byte ASN. Uses "asplain" format.  Example: `12345` (2-byte) or `1587232876` (4-byte)
     */
    customerAsn?: pulumi.Input<string>;
    /**
     * (Updatable) Deprecated. Instead use `customerAsn`. If you specify values for both, the request will be rejected.
     *
     * @deprecated The 'customer_bgp_asn' field has been deprecated. Please use 'customer_asn' instead.
     */
    customerBgpAsn?: pulumi.Input<number>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) For private virtual circuits only. The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the [dynamic routing gateway (DRG)](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Drg) that this virtual circuit uses.
     */
    gatewayId?: pulumi.Input<string>;
    /**
     * (Updatable) The layer 3 IP MTU to use with this virtual circuit.
     */
    ipMtu?: pulumi.Input<string>;
    /**
     * (Updatable) Set to `true` to enable BFD for IPv4 BGP peering, or set to `false` to disable BFD. If this is not set, the default is `false`.
     */
    isBfdEnabled?: pulumi.Input<boolean>;
    /**
     * (Updatable) Set to `true` for the virtual circuit to carry only encrypted traffic, or set to `false` for the virtual circuit to carry unencrypted traffic. If this is not set, the default is `false`.
     */
    isTransportMode?: pulumi.Input<boolean>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the service offered by the provider (if you're connecting via a provider). To get a list of the available service offerings, see [ListFastConnectProviderServices](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/FastConnectProviderService/ListFastConnectProviderServices).
     */
    providerServiceId?: pulumi.Input<string>;
    /**
     * (Updatable) The service key name offered by the provider (if the customer is connecting via a provider).
     */
    providerServiceKeyName?: pulumi.Input<string>;
    /**
     * (Updatable) For a public virtual circuit. The public IP prefixes (CIDRs) the customer wants to advertise across the connection.
     */
    publicPrefixes?: pulumi.Input<pulumi.Input<inputs.Core.VirtualCircuitPublicPrefix>[]>;
    /**
     * The Oracle Cloud Infrastructure region where this virtual circuit is located. Example: `phx`
     */
    region?: pulumi.Input<string>;
    /**
     * (Updatable) The routing policy sets how routing information about the Oracle cloud is shared over a public virtual circuit. Policies available are: `ORACLE_SERVICE_NETWORK`, `REGIONAL`, `MARKET_LEVEL`, and `GLOBAL`. See [Route Filtering](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/routingonprem.htm#route_filtering) for details. By default, routing information is shared for all routes in the same market.
     */
    routingPolicies?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * The type of IP addresses used in this virtual circuit. PRIVATE means [RFC 1918](https://tools.ietf.org/html/rfc1918) addresses (10.0.0.0/8, 172.16/12, and 192.168/16). 
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    type: pulumi.Input<string>;
}
