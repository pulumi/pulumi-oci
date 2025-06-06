// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This resource provides the Subnet resource in Oracle Cloud Infrastructure Core service.
 *
 * Creates a new subnet in the specified VCN. You can't change the size of the subnet after creation,
 * so it's important to think about the size of subnets you need before creating them.
 * For more information, see [VCNs and Subnets](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/managingVCNs.htm).
 * For information on the number of subnets you can have in a VCN, see
 * [Service Limits](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/servicelimits.htm).
 *
 * For the purposes of access control, you must provide the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want the subnet
 * to reside. Notice that the subnet doesn't have to be in the same compartment as the VCN, route tables, or
 * other Networking Service components. If you're not sure which compartment to use, put the subnet in
 * the same compartment as the VCN. For more information about compartments and access control, see
 * [Overview of the IAM Service](https://docs.cloud.oracle.com/iaas/Content/Identity/Concepts/overview.htm). For information about OCIDs,
 * see [Resource Identifiers](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
 *
 * You may optionally associate a route table with the subnet. If you don't, the subnet will use the
 * VCN's default route table. For more information about route tables, see
 * [Route Tables](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/managingroutetables.htm).
 *
 * You may optionally associate a security list with the subnet. If you don't, the subnet will use the
 * VCN's default security list. For more information about security lists, see
 * [Security Lists](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/securitylists.htm).
 *
 * You may optionally associate a set of DHCP options with the subnet. If you don't, the subnet will use the
 * VCN's default set. For more information about DHCP options, see
 * [DHCP Options](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/managingDHCP.htm).
 *
 * You may optionally specify a *display name* for the subnet, otherwise a default is provided.
 * It does not have to be unique, and you can change it. Avoid entering confidential information.
 *
 * You can also add a DNS label for the subnet, which is required if you want the Internet and
 * VCN Resolver to resolve hostnames for instances in the subnet. For more information, see
 * [DNS in Your Virtual Cloud Network](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/dns.htm).
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testSubnet = new oci.core.Subnet("test_subnet", {
 *     cidrBlock: subnetCidrBlock,
 *     compartmentId: compartmentId,
 *     vcnId: testVcn.id,
 *     availabilityDomain: subnetAvailabilityDomain,
 *     definedTags: {
 *         "Operations.CostCenter": "42",
 *     },
 *     dhcpOptionsId: testDhcpOptions.id,
 *     displayName: subnetDisplayName,
 *     dnsLabel: subnetDnsLabel,
 *     freeformTags: {
 *         Department: "Finance",
 *     },
 *     ipv6cidrBlock: subnetIpv6cidrBlock,
 *     ipv6cidrBlocks: subnetIpv6cidrBlocks,
 *     prohibitInternetIngress: subnetProhibitInternetIngress,
 *     prohibitPublicIpOnVnic: subnetProhibitPublicIpOnVnic,
 *     routeTableId: testRouteTable.id,
 *     securityListIds: subnetSecurityListIds,
 * });
 * ```
 *
 * ## Import
 *
 * Subnets can be imported using the `id`, e.g.
 *
 * ```sh
 * $ pulumi import oci:Core/subnet:Subnet test_subnet "id"
 * ```
 */
export class Subnet extends pulumi.CustomResource {
    /**
     * Get an existing Subnet resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: SubnetState, opts?: pulumi.CustomResourceOptions): Subnet {
        return new Subnet(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:Core/subnet:Subnet';

    /**
     * Returns true if the given object is an instance of Subnet.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is Subnet {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === Subnet.__pulumiType;
    }

    /**
     * Controls whether the subnet is regional or specific to an availability domain. Oracle recommends creating regional subnets because they're more flexible and make it easier to implement failover across availability domains. Originally, AD-specific subnets were the only kind available to use.
     *
     * To create a regional subnet, omit this attribute. Then any resources later created in this subnet (such as a Compute instance) can be created in any availability domain in the region.
     *
     * To instead create an AD-specific subnet, set this attribute to the availability domain you want this subnet to be in. Then any resources later created in this subnet can only be created in that availability domain.
     *
     * Example: `Uocm:PHX-AD-1`
     */
    public readonly availabilityDomain!: pulumi.Output<string>;
    /**
     * (Updatable) The CIDR IP address range of the subnet. The CIDR must maintain the following rules -
     *
     * a. The CIDR block is valid and correctly formatted. b. The new range is within one of the parent VCN ranges.
     *
     * Example: `10.0.1.0/24`
     */
    public readonly cidrBlock!: pulumi.Output<string>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to contain the subnet.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the set of DHCP options the subnet will use. If you don't provide a value, the subnet uses the VCN's default set of DHCP options.
     */
    public readonly dhcpOptionsId!: pulumi.Output<string>;
    /**
     * (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * A DNS label for the subnet, used in conjunction with the VNIC's hostname and VCN's DNS label to form a fully qualified domain name (FQDN) for each VNIC within this subnet (for example, `bminstance1.subnet123.vcn1.oraclevcn.com`). Must be an alphanumeric string that begins with a letter and is unique within the VCN. The value cannot be changed.
     *
     * This value must be set if you want to use the Internet and VCN Resolver to resolve the hostnames of instances in the subnet. It can only be set if the VCN itself was created with a DNS label.
     *
     * For more information, see [DNS in Your Virtual Cloud Network](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/dns.htm).
     *
     * Example: `subnet123`
     */
    public readonly dnsLabel!: pulumi.Output<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * (Updatable) Use this to enable IPv6 addressing for this subnet. The VCN must be enabled for IPv6. You can't change this subnet characteristic later. All subnets are /64 in size. The subnet portion of the IPv6 address is the fourth hextet from the left (1111 in the following example).
     *
     * For important details about IPv6 addressing in a VCN, see [IPv6 Addresses](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/ipv6.htm).
     *
     * Example: `2001:0db8:0123:1111::/64`
     */
    public readonly ipv6cidrBlock!: pulumi.Output<string>;
    /**
     * (Updatable) The list of all IPv6 prefixes (Oracle allocated IPv6 GUA, ULA or private IPv6 prefixes, BYOIPv6 prefixes) for the subnet that meets the following criteria:
     * * The prefixes must be valid.
     * * Multiple prefixes must not overlap each other or the on-premises network prefix.
     * * The number of prefixes must not exceed the limit of IPv6 prefixes allowed to a subnet.
     */
    public readonly ipv6cidrBlocks!: pulumi.Output<string[]>;
    /**
     * For an IPv6-enabled subnet, this is the IPv6 address of the virtual router.  Example: `2001:0db8:0123:1111:89ab:cdef:1234:5678`
     */
    public /*out*/ readonly ipv6virtualRouterIp!: pulumi.Output<string>;
    /**
     * Whether to disallow ingress internet traffic to VNICs within this subnet. Defaults to false.
     *
     * For IPv6, if `prohibitInternetIngress` is set to `true`, internet access is not allowed for any IPv6s assigned to VNICs in the subnet. Otherwise, ingress internet traffic is allowed by default.
     *
     * `prohibitPublicIpOnVnic` will be set to the value of `prohibitInternetIngress` to dictate IPv4 behavior in this subnet. Only one or the other flag should be specified.
     *
     * Example: `true`
     */
    public readonly prohibitInternetIngress!: pulumi.Output<boolean>;
    /**
     * Whether VNICs within this subnet can have public IP addresses. Defaults to false, which means VNICs created in this subnet will automatically be assigned public IP addresses unless specified otherwise during instance launch or VNIC creation (with the `assignPublicIp` flag in [CreateVnicDetails](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/CreateVnicDetails/)). If `prohibitPublicIpOnVnic` is set to true, VNICs created in this subnet cannot have public IP addresses (that is, it's a private subnet).
     *
     * If you intend to use an IPv6 prefix, you should use the flag `prohibitInternetIngress` to specify ingress internet traffic behavior of the subnet.
     *
     * Example: `true`
     */
    public readonly prohibitPublicIpOnVnic!: pulumi.Output<boolean>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the route table the subnet will use. If you don't provide a value, the subnet uses the VCN's default route table.
     */
    public readonly routeTableId!: pulumi.Output<string>;
    /**
     * (Updatable) The OCIDs of the security list or lists the subnet will use. If you don't provide a value, the subnet uses the VCN's default security list. Remember that security lists are associated *with the subnet*, but the rules are applied to the individual VNICs in the subnet.
     */
    public readonly securityListIds!: pulumi.Output<string[]>;
    /**
     * The subnet's current state.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * The subnet's domain name, which consists of the subnet's DNS label, the VCN's DNS label, and the `oraclevcn.com` domain.
     */
    public /*out*/ readonly subnetDomainName!: pulumi.Output<string>;
    /**
     * The date and time the subnet was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN to contain the subnet.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    public readonly vcnId!: pulumi.Output<string>;
    /**
     * The IP address of the virtual router.  Example: `10.0.14.1`
     */
    public /*out*/ readonly virtualRouterIp!: pulumi.Output<string>;
    /**
     * The MAC address of the virtual router.  Example: `00:00:00:00:00:01`
     */
    public /*out*/ readonly virtualRouterMac!: pulumi.Output<string>;

    /**
     * Create a Subnet resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: SubnetArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: SubnetArgs | SubnetState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as SubnetState | undefined;
            resourceInputs["availabilityDomain"] = state ? state.availabilityDomain : undefined;
            resourceInputs["cidrBlock"] = state ? state.cidrBlock : undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["dhcpOptionsId"] = state ? state.dhcpOptionsId : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["dnsLabel"] = state ? state.dnsLabel : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["ipv6cidrBlock"] = state ? state.ipv6cidrBlock : undefined;
            resourceInputs["ipv6cidrBlocks"] = state ? state.ipv6cidrBlocks : undefined;
            resourceInputs["ipv6virtualRouterIp"] = state ? state.ipv6virtualRouterIp : undefined;
            resourceInputs["prohibitInternetIngress"] = state ? state.prohibitInternetIngress : undefined;
            resourceInputs["prohibitPublicIpOnVnic"] = state ? state.prohibitPublicIpOnVnic : undefined;
            resourceInputs["routeTableId"] = state ? state.routeTableId : undefined;
            resourceInputs["securityListIds"] = state ? state.securityListIds : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["subnetDomainName"] = state ? state.subnetDomainName : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["vcnId"] = state ? state.vcnId : undefined;
            resourceInputs["virtualRouterIp"] = state ? state.virtualRouterIp : undefined;
            resourceInputs["virtualRouterMac"] = state ? state.virtualRouterMac : undefined;
        } else {
            const args = argsOrState as SubnetArgs | undefined;
            if ((!args || args.cidrBlock === undefined) && !opts.urn) {
                throw new Error("Missing required property 'cidrBlock'");
            }
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.vcnId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'vcnId'");
            }
            resourceInputs["availabilityDomain"] = args ? args.availabilityDomain : undefined;
            resourceInputs["cidrBlock"] = args ? args.cidrBlock : undefined;
            resourceInputs["compartmentId"] = args ? args.compartmentId : undefined;
            resourceInputs["definedTags"] = args ? args.definedTags : undefined;
            resourceInputs["dhcpOptionsId"] = args ? args.dhcpOptionsId : undefined;
            resourceInputs["displayName"] = args ? args.displayName : undefined;
            resourceInputs["dnsLabel"] = args ? args.dnsLabel : undefined;
            resourceInputs["freeformTags"] = args ? args.freeformTags : undefined;
            resourceInputs["ipv6cidrBlock"] = args ? args.ipv6cidrBlock : undefined;
            resourceInputs["ipv6cidrBlocks"] = args ? args.ipv6cidrBlocks : undefined;
            resourceInputs["prohibitInternetIngress"] = args ? args.prohibitInternetIngress : undefined;
            resourceInputs["prohibitPublicIpOnVnic"] = args ? args.prohibitPublicIpOnVnic : undefined;
            resourceInputs["routeTableId"] = args ? args.routeTableId : undefined;
            resourceInputs["securityListIds"] = args ? args.securityListIds : undefined;
            resourceInputs["vcnId"] = args ? args.vcnId : undefined;
            resourceInputs["ipv6virtualRouterIp"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["subnetDomainName"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["virtualRouterIp"] = undefined /*out*/;
            resourceInputs["virtualRouterMac"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(Subnet.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering Subnet resources.
 */
export interface SubnetState {
    /**
     * Controls whether the subnet is regional or specific to an availability domain. Oracle recommends creating regional subnets because they're more flexible and make it easier to implement failover across availability domains. Originally, AD-specific subnets were the only kind available to use.
     *
     * To create a regional subnet, omit this attribute. Then any resources later created in this subnet (such as a Compute instance) can be created in any availability domain in the region.
     *
     * To instead create an AD-specific subnet, set this attribute to the availability domain you want this subnet to be in. Then any resources later created in this subnet can only be created in that availability domain.
     *
     * Example: `Uocm:PHX-AD-1`
     */
    availabilityDomain?: pulumi.Input<string>;
    /**
     * (Updatable) The CIDR IP address range of the subnet. The CIDR must maintain the following rules -
     *
     * a. The CIDR block is valid and correctly formatted. b. The new range is within one of the parent VCN ranges.
     *
     * Example: `10.0.1.0/24`
     */
    cidrBlock?: pulumi.Input<string>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to contain the subnet.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the set of DHCP options the subnet will use. If you don't provide a value, the subnet uses the VCN's default set of DHCP options.
     */
    dhcpOptionsId?: pulumi.Input<string>;
    /**
     * (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
     */
    displayName?: pulumi.Input<string>;
    /**
     * A DNS label for the subnet, used in conjunction with the VNIC's hostname and VCN's DNS label to form a fully qualified domain name (FQDN) for each VNIC within this subnet (for example, `bminstance1.subnet123.vcn1.oraclevcn.com`). Must be an alphanumeric string that begins with a letter and is unique within the VCN. The value cannot be changed.
     *
     * This value must be set if you want to use the Internet and VCN Resolver to resolve the hostnames of instances in the subnet. It can only be set if the VCN itself was created with a DNS label.
     *
     * For more information, see [DNS in Your Virtual Cloud Network](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/dns.htm).
     *
     * Example: `subnet123`
     */
    dnsLabel?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) Use this to enable IPv6 addressing for this subnet. The VCN must be enabled for IPv6. You can't change this subnet characteristic later. All subnets are /64 in size. The subnet portion of the IPv6 address is the fourth hextet from the left (1111 in the following example).
     *
     * For important details about IPv6 addressing in a VCN, see [IPv6 Addresses](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/ipv6.htm).
     *
     * Example: `2001:0db8:0123:1111::/64`
     */
    ipv6cidrBlock?: pulumi.Input<string>;
    /**
     * (Updatable) The list of all IPv6 prefixes (Oracle allocated IPv6 GUA, ULA or private IPv6 prefixes, BYOIPv6 prefixes) for the subnet that meets the following criteria:
     * * The prefixes must be valid.
     * * Multiple prefixes must not overlap each other or the on-premises network prefix.
     * * The number of prefixes must not exceed the limit of IPv6 prefixes allowed to a subnet.
     */
    ipv6cidrBlocks?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * For an IPv6-enabled subnet, this is the IPv6 address of the virtual router.  Example: `2001:0db8:0123:1111:89ab:cdef:1234:5678`
     */
    ipv6virtualRouterIp?: pulumi.Input<string>;
    /**
     * Whether to disallow ingress internet traffic to VNICs within this subnet. Defaults to false.
     *
     * For IPv6, if `prohibitInternetIngress` is set to `true`, internet access is not allowed for any IPv6s assigned to VNICs in the subnet. Otherwise, ingress internet traffic is allowed by default.
     *
     * `prohibitPublicIpOnVnic` will be set to the value of `prohibitInternetIngress` to dictate IPv4 behavior in this subnet. Only one or the other flag should be specified.
     *
     * Example: `true`
     */
    prohibitInternetIngress?: pulumi.Input<boolean>;
    /**
     * Whether VNICs within this subnet can have public IP addresses. Defaults to false, which means VNICs created in this subnet will automatically be assigned public IP addresses unless specified otherwise during instance launch or VNIC creation (with the `assignPublicIp` flag in [CreateVnicDetails](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/CreateVnicDetails/)). If `prohibitPublicIpOnVnic` is set to true, VNICs created in this subnet cannot have public IP addresses (that is, it's a private subnet).
     *
     * If you intend to use an IPv6 prefix, you should use the flag `prohibitInternetIngress` to specify ingress internet traffic behavior of the subnet.
     *
     * Example: `true`
     */
    prohibitPublicIpOnVnic?: pulumi.Input<boolean>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the route table the subnet will use. If you don't provide a value, the subnet uses the VCN's default route table.
     */
    routeTableId?: pulumi.Input<string>;
    /**
     * (Updatable) The OCIDs of the security list or lists the subnet will use. If you don't provide a value, the subnet uses the VCN's default security list. Remember that security lists are associated *with the subnet*, but the rules are applied to the individual VNICs in the subnet.
     */
    securityListIds?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * The subnet's current state.
     */
    state?: pulumi.Input<string>;
    /**
     * The subnet's domain name, which consists of the subnet's DNS label, the VCN's DNS label, and the `oraclevcn.com` domain.
     */
    subnetDomainName?: pulumi.Input<string>;
    /**
     * The date and time the subnet was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN to contain the subnet.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    vcnId?: pulumi.Input<string>;
    /**
     * The IP address of the virtual router.  Example: `10.0.14.1`
     */
    virtualRouterIp?: pulumi.Input<string>;
    /**
     * The MAC address of the virtual router.  Example: `00:00:00:00:00:01`
     */
    virtualRouterMac?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a Subnet resource.
 */
export interface SubnetArgs {
    /**
     * Controls whether the subnet is regional or specific to an availability domain. Oracle recommends creating regional subnets because they're more flexible and make it easier to implement failover across availability domains. Originally, AD-specific subnets were the only kind available to use.
     *
     * To create a regional subnet, omit this attribute. Then any resources later created in this subnet (such as a Compute instance) can be created in any availability domain in the region.
     *
     * To instead create an AD-specific subnet, set this attribute to the availability domain you want this subnet to be in. Then any resources later created in this subnet can only be created in that availability domain.
     *
     * Example: `Uocm:PHX-AD-1`
     */
    availabilityDomain?: pulumi.Input<string>;
    /**
     * (Updatable) The CIDR IP address range of the subnet. The CIDR must maintain the following rules -
     *
     * a. The CIDR block is valid and correctly formatted. b. The new range is within one of the parent VCN ranges.
     *
     * Example: `10.0.1.0/24`
     */
    cidrBlock: pulumi.Input<string>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to contain the subnet.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the set of DHCP options the subnet will use. If you don't provide a value, the subnet uses the VCN's default set of DHCP options.
     */
    dhcpOptionsId?: pulumi.Input<string>;
    /**
     * (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
     */
    displayName?: pulumi.Input<string>;
    /**
     * A DNS label for the subnet, used in conjunction with the VNIC's hostname and VCN's DNS label to form a fully qualified domain name (FQDN) for each VNIC within this subnet (for example, `bminstance1.subnet123.vcn1.oraclevcn.com`). Must be an alphanumeric string that begins with a letter and is unique within the VCN. The value cannot be changed.
     *
     * This value must be set if you want to use the Internet and VCN Resolver to resolve the hostnames of instances in the subnet. It can only be set if the VCN itself was created with a DNS label.
     *
     * For more information, see [DNS in Your Virtual Cloud Network](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/dns.htm).
     *
     * Example: `subnet123`
     */
    dnsLabel?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) Use this to enable IPv6 addressing for this subnet. The VCN must be enabled for IPv6. You can't change this subnet characteristic later. All subnets are /64 in size. The subnet portion of the IPv6 address is the fourth hextet from the left (1111 in the following example).
     *
     * For important details about IPv6 addressing in a VCN, see [IPv6 Addresses](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/ipv6.htm).
     *
     * Example: `2001:0db8:0123:1111::/64`
     */
    ipv6cidrBlock?: pulumi.Input<string>;
    /**
     * (Updatable) The list of all IPv6 prefixes (Oracle allocated IPv6 GUA, ULA or private IPv6 prefixes, BYOIPv6 prefixes) for the subnet that meets the following criteria:
     * * The prefixes must be valid.
     * * Multiple prefixes must not overlap each other or the on-premises network prefix.
     * * The number of prefixes must not exceed the limit of IPv6 prefixes allowed to a subnet.
     */
    ipv6cidrBlocks?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * Whether to disallow ingress internet traffic to VNICs within this subnet. Defaults to false.
     *
     * For IPv6, if `prohibitInternetIngress` is set to `true`, internet access is not allowed for any IPv6s assigned to VNICs in the subnet. Otherwise, ingress internet traffic is allowed by default.
     *
     * `prohibitPublicIpOnVnic` will be set to the value of `prohibitInternetIngress` to dictate IPv4 behavior in this subnet. Only one or the other flag should be specified.
     *
     * Example: `true`
     */
    prohibitInternetIngress?: pulumi.Input<boolean>;
    /**
     * Whether VNICs within this subnet can have public IP addresses. Defaults to false, which means VNICs created in this subnet will automatically be assigned public IP addresses unless specified otherwise during instance launch or VNIC creation (with the `assignPublicIp` flag in [CreateVnicDetails](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/CreateVnicDetails/)). If `prohibitPublicIpOnVnic` is set to true, VNICs created in this subnet cannot have public IP addresses (that is, it's a private subnet).
     *
     * If you intend to use an IPv6 prefix, you should use the flag `prohibitInternetIngress` to specify ingress internet traffic behavior of the subnet.
     *
     * Example: `true`
     */
    prohibitPublicIpOnVnic?: pulumi.Input<boolean>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the route table the subnet will use. If you don't provide a value, the subnet uses the VCN's default route table.
     */
    routeTableId?: pulumi.Input<string>;
    /**
     * (Updatable) The OCIDs of the security list or lists the subnet will use. If you don't provide a value, the subnet uses the VCN's default security list. Remember that security lists are associated *with the subnet*, but the rules are applied to the individual VNICs in the subnet.
     */
    securityListIds?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN to contain the subnet.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    vcnId: pulumi.Input<string>;
}
