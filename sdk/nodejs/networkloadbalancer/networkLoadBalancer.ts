// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This resource provides the Network Load Balancer resource in Oracle Cloud Infrastructure Network Load Balancer service.
 *
 * Creates a network load balancer.
 *
 * ## Import
 *
 * NetworkLoadBalancers can be imported using the `id`, e.g.
 *
 * ```sh
 * $ pulumi import oci:NetworkLoadBalancer/networkLoadBalancer:NetworkLoadBalancer test_network_load_balancer "id"
 * ```
 */
export class NetworkLoadBalancer extends pulumi.CustomResource {
    /**
     * Get an existing NetworkLoadBalancer resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: NetworkLoadBalancerState, opts?: pulumi.CustomResourceOptions): NetworkLoadBalancer {
        return new NetworkLoadBalancer(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:NetworkLoadBalancer/networkLoadBalancer:NetworkLoadBalancer';

    /**
     * Returns true if the given object is an instance of NetworkLoadBalancer.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is NetworkLoadBalancer {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === NetworkLoadBalancer.__pulumiType;
    }

    /**
     * IPv6 address to be assigned to the network load balancer being created. This IP address has to be part of one of the prefixes supported by the subnet. Example: "2607:9b80:9a0a:9a7e:abcd:ef01:2345:6789"
     */
    public readonly assignedIpv6!: pulumi.Output<string | undefined>;
    /**
     * Private IP address to be assigned to the network load balancer being created. This IP address has to be in the CIDR range of the subnet where network load balancer is being created Example: "10.0.0.1"
     */
    public readonly assignedPrivateIpv4!: pulumi.Output<string | undefined>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the network load balancer.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * (Updatable) Network load balancer identifier, which can be renamed.
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * An array of IP addresses.
     */
    public /*out*/ readonly ipAddresses!: pulumi.Output<outputs.NetworkLoadBalancer.NetworkLoadBalancerIpAddress[]>;
    /**
     * (Updatable) This parameter can be enabled only if backends are compute OCIDs. When enabled, the skipSourceDestinationCheck parameter is automatically enabled on the load balancer VNIC, and packets are sent to the backend with the entire IP header intact.
     */
    public readonly isPreserveSourceDestination!: pulumi.Output<boolean>;
    /**
     * Whether the network load balancer has a virtual cloud network-local (private) IP address.
     *
     * If "true", then the service assigns a private IP address to the network load balancer.
     *
     * If "false", then the service assigns a public IP address to the network load balancer.
     *
     * A public network load balancer is accessible from the internet, depending on the [security list rules](https://docs.cloud.oracle.com/iaas/Content/network/Concepts/securitylists.htm) for your virtual cloud network. For more information about public and private network load balancers, see [Network Load Balancer Types](https://docs.cloud.oracle.com/iaas/Content/NetworkLoadBalancer/introduction.htm#NetworkLoadBalancerTypes). This value is true by default.
     *
     * Example: `true`
     */
    public readonly isPrivate!: pulumi.Output<boolean>;
    /**
     * (Updatable) This can only be enabled when NLB is working in transparent mode with source destination header preservation enabled.  This removes the additional dependency from NLB backends(like Firewalls) to perform SNAT. 
     *
     * Example: `true`
     * Example: `true`
     */
    public readonly isSymmetricHashEnabled!: pulumi.Output<boolean>;
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     */
    public /*out*/ readonly lifecycleDetails!: pulumi.Output<string>;
    /**
     * (Updatable) An array of network security groups [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) associated with the network load balancer.
     *
     * During the creation of the network load balancer, the service adds the new load balancer to the specified network security groups.
     *
     * The benefits of associating the network load balancer with network security groups include:
     * *  Network security groups define network security rules to govern ingress and egress traffic for the network load balancer.
     * *  The network security rules of other resources can reference the network security groups associated with the network load balancer to ensure access.
     *
     * Example: ["ocid1.nsg.oc1.phx.unique_ID"]
     */
    public readonly networkSecurityGroupIds!: pulumi.Output<string[] | undefined>;
    /**
     * (Updatable) IP version associated with the NLB.
     */
    public readonly nlbIpVersion!: pulumi.Output<string>;
    /**
     * An array of reserved Ips.
     */
    public readonly reservedIps!: pulumi.Output<outputs.NetworkLoadBalancer.NetworkLoadBalancerReservedIp[]>;
    /**
     * (Updatable) ZPR tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"oracle-zpr": {"td": {"value": "42", "mode": "audit"}}}`
     */
    public readonly securityAttributes!: pulumi.Output<{[key: string]: string}>;
    /**
     * The current state of the network load balancer.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * The subnet in which the network load balancer is spawned [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    public readonly subnetId!: pulumi.Output<string>;
    /**
     * IPv6 subnet prefix selection. If Ipv6 subnet prefix is passed, Nlb Ipv6 Address would be assign within the cidr block. NLB has to be dual or single stack ipv6 to support this.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    public readonly subnetIpv6cidr!: pulumi.Output<string | undefined>;
    /**
     * Key-value pair representing system tags' keys and values scoped to a namespace. Example: `{"bar-key": "value"}`
     */
    public /*out*/ readonly systemTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * The date and time the network load balancer was created, in the format defined by RFC3339.  Example: `2020-05-01T21:10:29.600Z`
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The time the network load balancer was updated. An RFC3339 formatted date-time string.  Example: `2020-05-01T22:10:29.600Z`
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;

    /**
     * Create a NetworkLoadBalancer resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: NetworkLoadBalancerArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: NetworkLoadBalancerArgs | NetworkLoadBalancerState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as NetworkLoadBalancerState | undefined;
            resourceInputs["assignedIpv6"] = state ? state.assignedIpv6 : undefined;
            resourceInputs["assignedPrivateIpv4"] = state ? state.assignedPrivateIpv4 : undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["ipAddresses"] = state ? state.ipAddresses : undefined;
            resourceInputs["isPreserveSourceDestination"] = state ? state.isPreserveSourceDestination : undefined;
            resourceInputs["isPrivate"] = state ? state.isPrivate : undefined;
            resourceInputs["isSymmetricHashEnabled"] = state ? state.isSymmetricHashEnabled : undefined;
            resourceInputs["lifecycleDetails"] = state ? state.lifecycleDetails : undefined;
            resourceInputs["networkSecurityGroupIds"] = state ? state.networkSecurityGroupIds : undefined;
            resourceInputs["nlbIpVersion"] = state ? state.nlbIpVersion : undefined;
            resourceInputs["reservedIps"] = state ? state.reservedIps : undefined;
            resourceInputs["securityAttributes"] = state ? state.securityAttributes : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["subnetId"] = state ? state.subnetId : undefined;
            resourceInputs["subnetIpv6cidr"] = state ? state.subnetIpv6cidr : undefined;
            resourceInputs["systemTags"] = state ? state.systemTags : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeUpdated"] = state ? state.timeUpdated : undefined;
        } else {
            const args = argsOrState as NetworkLoadBalancerArgs | undefined;
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.displayName === undefined) && !opts.urn) {
                throw new Error("Missing required property 'displayName'");
            }
            if ((!args || args.subnetId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'subnetId'");
            }
            resourceInputs["assignedIpv6"] = args ? args.assignedIpv6 : undefined;
            resourceInputs["assignedPrivateIpv4"] = args ? args.assignedPrivateIpv4 : undefined;
            resourceInputs["compartmentId"] = args ? args.compartmentId : undefined;
            resourceInputs["definedTags"] = args ? args.definedTags : undefined;
            resourceInputs["displayName"] = args ? args.displayName : undefined;
            resourceInputs["freeformTags"] = args ? args.freeformTags : undefined;
            resourceInputs["isPreserveSourceDestination"] = args ? args.isPreserveSourceDestination : undefined;
            resourceInputs["isPrivate"] = args ? args.isPrivate : undefined;
            resourceInputs["isSymmetricHashEnabled"] = args ? args.isSymmetricHashEnabled : undefined;
            resourceInputs["networkSecurityGroupIds"] = args ? args.networkSecurityGroupIds : undefined;
            resourceInputs["nlbIpVersion"] = args ? args.nlbIpVersion : undefined;
            resourceInputs["reservedIps"] = args ? args.reservedIps : undefined;
            resourceInputs["securityAttributes"] = args ? args.securityAttributes : undefined;
            resourceInputs["subnetId"] = args ? args.subnetId : undefined;
            resourceInputs["subnetIpv6cidr"] = args ? args.subnetIpv6cidr : undefined;
            resourceInputs["ipAddresses"] = undefined /*out*/;
            resourceInputs["lifecycleDetails"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["systemTags"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeUpdated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(NetworkLoadBalancer.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering NetworkLoadBalancer resources.
 */
export interface NetworkLoadBalancerState {
    /**
     * IPv6 address to be assigned to the network load balancer being created. This IP address has to be part of one of the prefixes supported by the subnet. Example: "2607:9b80:9a0a:9a7e:abcd:ef01:2345:6789"
     */
    assignedIpv6?: pulumi.Input<string>;
    /**
     * Private IP address to be assigned to the network load balancer being created. This IP address has to be in the CIDR range of the subnet where network load balancer is being created Example: "10.0.0.1"
     */
    assignedPrivateIpv4?: pulumi.Input<string>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the network load balancer.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) Network load balancer identifier, which can be renamed.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * An array of IP addresses.
     */
    ipAddresses?: pulumi.Input<pulumi.Input<inputs.NetworkLoadBalancer.NetworkLoadBalancerIpAddress>[]>;
    /**
     * (Updatable) This parameter can be enabled only if backends are compute OCIDs. When enabled, the skipSourceDestinationCheck parameter is automatically enabled on the load balancer VNIC, and packets are sent to the backend with the entire IP header intact.
     */
    isPreserveSourceDestination?: pulumi.Input<boolean>;
    /**
     * Whether the network load balancer has a virtual cloud network-local (private) IP address.
     *
     * If "true", then the service assigns a private IP address to the network load balancer.
     *
     * If "false", then the service assigns a public IP address to the network load balancer.
     *
     * A public network load balancer is accessible from the internet, depending on the [security list rules](https://docs.cloud.oracle.com/iaas/Content/network/Concepts/securitylists.htm) for your virtual cloud network. For more information about public and private network load balancers, see [Network Load Balancer Types](https://docs.cloud.oracle.com/iaas/Content/NetworkLoadBalancer/introduction.htm#NetworkLoadBalancerTypes). This value is true by default.
     *
     * Example: `true`
     */
    isPrivate?: pulumi.Input<boolean>;
    /**
     * (Updatable) This can only be enabled when NLB is working in transparent mode with source destination header preservation enabled.  This removes the additional dependency from NLB backends(like Firewalls) to perform SNAT. 
     *
     * Example: `true`
     * Example: `true`
     */
    isSymmetricHashEnabled?: pulumi.Input<boolean>;
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     */
    lifecycleDetails?: pulumi.Input<string>;
    /**
     * (Updatable) An array of network security groups [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) associated with the network load balancer.
     *
     * During the creation of the network load balancer, the service adds the new load balancer to the specified network security groups.
     *
     * The benefits of associating the network load balancer with network security groups include:
     * *  Network security groups define network security rules to govern ingress and egress traffic for the network load balancer.
     * *  The network security rules of other resources can reference the network security groups associated with the network load balancer to ensure access.
     *
     * Example: ["ocid1.nsg.oc1.phx.unique_ID"]
     */
    networkSecurityGroupIds?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * (Updatable) IP version associated with the NLB.
     */
    nlbIpVersion?: pulumi.Input<string>;
    /**
     * An array of reserved Ips.
     */
    reservedIps?: pulumi.Input<pulumi.Input<inputs.NetworkLoadBalancer.NetworkLoadBalancerReservedIp>[]>;
    /**
     * (Updatable) ZPR tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"oracle-zpr": {"td": {"value": "42", "mode": "audit"}}}`
     */
    securityAttributes?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * The current state of the network load balancer.
     */
    state?: pulumi.Input<string>;
    /**
     * The subnet in which the network load balancer is spawned [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    subnetId?: pulumi.Input<string>;
    /**
     * IPv6 subnet prefix selection. If Ipv6 subnet prefix is passed, Nlb Ipv6 Address would be assign within the cidr block. NLB has to be dual or single stack ipv6 to support this.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    subnetIpv6cidr?: pulumi.Input<string>;
    /**
     * Key-value pair representing system tags' keys and values scoped to a namespace. Example: `{"bar-key": "value"}`
     */
    systemTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * The date and time the network load balancer was created, in the format defined by RFC3339.  Example: `2020-05-01T21:10:29.600Z`
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The time the network load balancer was updated. An RFC3339 formatted date-time string.  Example: `2020-05-01T22:10:29.600Z`
     */
    timeUpdated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a NetworkLoadBalancer resource.
 */
export interface NetworkLoadBalancerArgs {
    /**
     * IPv6 address to be assigned to the network load balancer being created. This IP address has to be part of one of the prefixes supported by the subnet. Example: "2607:9b80:9a0a:9a7e:abcd:ef01:2345:6789"
     */
    assignedIpv6?: pulumi.Input<string>;
    /**
     * Private IP address to be assigned to the network load balancer being created. This IP address has to be in the CIDR range of the subnet where network load balancer is being created Example: "10.0.0.1"
     */
    assignedPrivateIpv4?: pulumi.Input<string>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the network load balancer.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) Network load balancer identifier, which can be renamed.
     */
    displayName: pulumi.Input<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) This parameter can be enabled only if backends are compute OCIDs. When enabled, the skipSourceDestinationCheck parameter is automatically enabled on the load balancer VNIC, and packets are sent to the backend with the entire IP header intact.
     */
    isPreserveSourceDestination?: pulumi.Input<boolean>;
    /**
     * Whether the network load balancer has a virtual cloud network-local (private) IP address.
     *
     * If "true", then the service assigns a private IP address to the network load balancer.
     *
     * If "false", then the service assigns a public IP address to the network load balancer.
     *
     * A public network load balancer is accessible from the internet, depending on the [security list rules](https://docs.cloud.oracle.com/iaas/Content/network/Concepts/securitylists.htm) for your virtual cloud network. For more information about public and private network load balancers, see [Network Load Balancer Types](https://docs.cloud.oracle.com/iaas/Content/NetworkLoadBalancer/introduction.htm#NetworkLoadBalancerTypes). This value is true by default.
     *
     * Example: `true`
     */
    isPrivate?: pulumi.Input<boolean>;
    /**
     * (Updatable) This can only be enabled when NLB is working in transparent mode with source destination header preservation enabled.  This removes the additional dependency from NLB backends(like Firewalls) to perform SNAT. 
     *
     * Example: `true`
     * Example: `true`
     */
    isSymmetricHashEnabled?: pulumi.Input<boolean>;
    /**
     * (Updatable) An array of network security groups [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) associated with the network load balancer.
     *
     * During the creation of the network load balancer, the service adds the new load balancer to the specified network security groups.
     *
     * The benefits of associating the network load balancer with network security groups include:
     * *  Network security groups define network security rules to govern ingress and egress traffic for the network load balancer.
     * *  The network security rules of other resources can reference the network security groups associated with the network load balancer to ensure access.
     *
     * Example: ["ocid1.nsg.oc1.phx.unique_ID"]
     */
    networkSecurityGroupIds?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * (Updatable) IP version associated with the NLB.
     */
    nlbIpVersion?: pulumi.Input<string>;
    /**
     * An array of reserved Ips.
     */
    reservedIps?: pulumi.Input<pulumi.Input<inputs.NetworkLoadBalancer.NetworkLoadBalancerReservedIp>[]>;
    /**
     * (Updatable) ZPR tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"oracle-zpr": {"td": {"value": "42", "mode": "audit"}}}`
     */
    securityAttributes?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * The subnet in which the network load balancer is spawned [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    subnetId: pulumi.Input<string>;
    /**
     * IPv6 subnet prefix selection. If Ipv6 subnet prefix is passed, Nlb Ipv6 Address would be assign within the cidr block. NLB has to be dual or single stack ipv6 to support this.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    subnetIpv6cidr?: pulumi.Input<string>;
}
