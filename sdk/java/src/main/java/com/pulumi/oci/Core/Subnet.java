// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.Core.SubnetArgs;
import com.pulumi.oci.Core.inputs.SubnetState;
import com.pulumi.oci.Utilities;
import java.lang.Boolean;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This resource provides the Subnet resource in Oracle Cloud Infrastructure Core service.
 * 
 * Creates a new subnet in the specified VCN. You can&#39;t change the size of the subnet after creation,
 * so it&#39;s important to think about the size of subnets you need before creating them.
 * For more information, see [VCNs and Subnets](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/managingVCNs.htm).
 * For information on the number of subnets you can have in a VCN, see
 * [Service Limits](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/servicelimits.htm).
 * 
 * For the purposes of access control, you must provide the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want the subnet
 * to reside. Notice that the subnet doesn&#39;t have to be in the same compartment as the VCN, route tables, or
 * other Networking Service components. If you&#39;re not sure which compartment to use, put the subnet in
 * the same compartment as the VCN. For more information about compartments and access control, see
 * [Overview of the IAM Service](https://docs.cloud.oracle.com/iaas/Content/Identity/Concepts/overview.htm). For information about OCIDs,
 * see [Resource Identifiers](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
 * 
 * You may optionally associate a route table with the subnet. If you don&#39;t, the subnet will use the
 * VCN&#39;s default route table. For more information about route tables, see
 * [Route Tables](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/managingroutetables.htm).
 * 
 * You may optionally associate a security list with the subnet. If you don&#39;t, the subnet will use the
 * VCN&#39;s default security list. For more information about security lists, see
 * [Security Lists](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/securitylists.htm).
 * 
 * You may optionally associate a set of DHCP options with the subnet. If you don&#39;t, the subnet will use the
 * VCN&#39;s default set. For more information about DHCP options, see
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
 * ## Import
 * 
 * Subnets can be imported using the `id`, e.g.
 * 
 * ```sh
 *  $ pulumi import oci:Core/subnet:Subnet test_subnet &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:Core/subnet:Subnet")
public class Subnet extends com.pulumi.resources.CustomResource {
    /**
     * Controls whether the subnet is regional or specific to an availability domain. Oracle recommends creating regional subnets because they&#39;re more flexible and make it easier to implement failover across availability domains. Originally, AD-specific subnets were the only kind available to use.
     * 
     */
    @Export(name="availabilityDomain", type=String.class, parameters={})
    private Output<String> availabilityDomain;

    /**
     * @return Controls whether the subnet is regional or specific to an availability domain. Oracle recommends creating regional subnets because they&#39;re more flexible and make it easier to implement failover across availability domains. Originally, AD-specific subnets were the only kind available to use.
     * 
     */
    public Output<String> availabilityDomain() {
        return this.availabilityDomain;
    }
    /**
     * (Updatable) The CIDR IP address range of the subnet. The CIDR must maintain the following rules -
     * 
     */
    @Export(name="cidrBlock", type=String.class, parameters={})
    private Output<String> cidrBlock;

    /**
     * @return (Updatable) The CIDR IP address range of the subnet. The CIDR must maintain the following rules -
     * 
     */
    public Output<String> cidrBlock() {
        return this.cidrBlock;
    }
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to contain the subnet.
     * 
     */
    @Export(name="compartmentId", type=String.class, parameters={})
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to contain the subnet.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    @Export(name="definedTags", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Output<Map<String,Object>> definedTags() {
        return this.definedTags;
    }
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the set of DHCP options the subnet will use. If you don&#39;t provide a value, the subnet uses the VCN&#39;s default set of DHCP options.
     * 
     */
    @Export(name="dhcpOptionsId", type=String.class, parameters={})
    private Output<String> dhcpOptionsId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the set of DHCP options the subnet will use. If you don&#39;t provide a value, the subnet uses the VCN&#39;s default set of DHCP options.
     * 
     */
    public Output<String> dhcpOptionsId() {
        return this.dhcpOptionsId;
    }
    /**
     * (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    @Export(name="displayName", type=String.class, parameters={})
    private Output<String> displayName;

    /**
     * @return (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }
    /**
     * A DNS label for the subnet, used in conjunction with the VNIC&#39;s hostname and VCN&#39;s DNS label to form a fully qualified domain name (FQDN) for each VNIC within this subnet (for example, `bminstance-1.subnet123.vcn1.oraclevcn.com`). Must be an alphanumeric string that begins with a letter and is unique within the VCN. The value cannot be changed.
     * 
     */
    @Export(name="dnsLabel", type=String.class, parameters={})
    private Output<String> dnsLabel;

    /**
     * @return A DNS label for the subnet, used in conjunction with the VNIC&#39;s hostname and VCN&#39;s DNS label to form a fully qualified domain name (FQDN) for each VNIC within this subnet (for example, `bminstance-1.subnet123.vcn1.oraclevcn.com`). Must be an alphanumeric string that begins with a letter and is unique within the VCN. The value cannot be changed.
     * 
     */
    public Output<String> dnsLabel() {
        return this.dnsLabel;
    }
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Export(name="freeformTags", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Output<Map<String,Object>> freeformTags() {
        return this.freeformTags;
    }
    /**
     * (Updatable) Use this to enable IPv6 addressing for this subnet. The VCN must be enabled for IPv6. You can&#39;t change this subnet characteristic later. All subnets are /64 in size. The subnet portion of the IPv6 address is the fourth hextet from the left (1111 in the following example).
     * 
     */
    @Export(name="ipv6cidrBlock", type=String.class, parameters={})
    private Output<String> ipv6cidrBlock;

    /**
     * @return (Updatable) Use this to enable IPv6 addressing for this subnet. The VCN must be enabled for IPv6. You can&#39;t change this subnet characteristic later. All subnets are /64 in size. The subnet portion of the IPv6 address is the fourth hextet from the left (1111 in the following example).
     * 
     */
    public Output<String> ipv6cidrBlock() {
        return this.ipv6cidrBlock;
    }
    /**
     * (Updatable) The list of all IPv6 CIDR blocks (Oracle allocated IPv6 GUA, ULA or private IPv6 CIDR blocks, BYOIPv6 CIDR blocks) for the subnet that meets the following criteria:
     * * The CIDR blocks must be valid.
     * * Multiple CIDR blocks must not overlap each other or the on-premises network CIDR block.
     * * The number of CIDR blocks must not exceed the limit of IPv6 CIDR blocks allowed to a subnet.
     * 
     */
    @Export(name="ipv6cidrBlocks", type=List.class, parameters={String.class})
    private Output<List<String>> ipv6cidrBlocks;

    /**
     * @return (Updatable) The list of all IPv6 CIDR blocks (Oracle allocated IPv6 GUA, ULA or private IPv6 CIDR blocks, BYOIPv6 CIDR blocks) for the subnet that meets the following criteria:
     * * The CIDR blocks must be valid.
     * * Multiple CIDR blocks must not overlap each other or the on-premises network CIDR block.
     * * The number of CIDR blocks must not exceed the limit of IPv6 CIDR blocks allowed to a subnet.
     * 
     */
    public Output<List<String>> ipv6cidrBlocks() {
        return this.ipv6cidrBlocks;
    }
    /**
     * For an IPv6-enabled subnet, this is the IPv6 address of the virtual router.  Example: `2001:0db8:0123:1111:89ab:cdef:1234:5678`
     * 
     */
    @Export(name="ipv6virtualRouterIp", type=String.class, parameters={})
    private Output<String> ipv6virtualRouterIp;

    /**
     * @return For an IPv6-enabled subnet, this is the IPv6 address of the virtual router.  Example: `2001:0db8:0123:1111:89ab:cdef:1234:5678`
     * 
     */
    public Output<String> ipv6virtualRouterIp() {
        return this.ipv6virtualRouterIp;
    }
    /**
     * Whether to disallow ingress internet traffic to VNICs within this subnet. Defaults to false.
     * 
     */
    @Export(name="prohibitInternetIngress", type=Boolean.class, parameters={})
    private Output<Boolean> prohibitInternetIngress;

    /**
     * @return Whether to disallow ingress internet traffic to VNICs within this subnet. Defaults to false.
     * 
     */
    public Output<Boolean> prohibitInternetIngress() {
        return this.prohibitInternetIngress;
    }
    /**
     * Whether VNICs within this subnet can have public IP addresses. Defaults to false, which means VNICs created in this subnet will automatically be assigned public IP addresses unless specified otherwise during instance launch or VNIC creation (with the `assignPublicIp` flag in [CreateVnicDetails](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/CreateVnicDetails/)). If `prohibitPublicIpOnVnic` is set to true, VNICs created in this subnet cannot have public IP addresses (that is, it&#39;s a private subnet).
     * 
     */
    @Export(name="prohibitPublicIpOnVnic", type=Boolean.class, parameters={})
    private Output<Boolean> prohibitPublicIpOnVnic;

    /**
     * @return Whether VNICs within this subnet can have public IP addresses. Defaults to false, which means VNICs created in this subnet will automatically be assigned public IP addresses unless specified otherwise during instance launch or VNIC creation (with the `assignPublicIp` flag in [CreateVnicDetails](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/CreateVnicDetails/)). If `prohibitPublicIpOnVnic` is set to true, VNICs created in this subnet cannot have public IP addresses (that is, it&#39;s a private subnet).
     * 
     */
    public Output<Boolean> prohibitPublicIpOnVnic() {
        return this.prohibitPublicIpOnVnic;
    }
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the route table the subnet will use. If you don&#39;t provide a value, the subnet uses the VCN&#39;s default route table.
     * 
     */
    @Export(name="routeTableId", type=String.class, parameters={})
    private Output<String> routeTableId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the route table the subnet will use. If you don&#39;t provide a value, the subnet uses the VCN&#39;s default route table.
     * 
     */
    public Output<String> routeTableId() {
        return this.routeTableId;
    }
    /**
     * (Updatable) The OCIDs of the security list or lists the subnet will use. If you don&#39;t provide a value, the subnet uses the VCN&#39;s default security list. Remember that security lists are associated *with the subnet*, but the rules are applied to the individual VNICs in the subnet.
     * 
     */
    @Export(name="securityListIds", type=List.class, parameters={String.class})
    private Output<List<String>> securityListIds;

    /**
     * @return (Updatable) The OCIDs of the security list or lists the subnet will use. If you don&#39;t provide a value, the subnet uses the VCN&#39;s default security list. Remember that security lists are associated *with the subnet*, but the rules are applied to the individual VNICs in the subnet.
     * 
     */
    public Output<List<String>> securityListIds() {
        return this.securityListIds;
    }
    /**
     * The subnet&#39;s current state.
     * 
     */
    @Export(name="state", type=String.class, parameters={})
    private Output<String> state;

    /**
     * @return The subnet&#39;s current state.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * The subnet&#39;s domain name, which consists of the subnet&#39;s DNS label, the VCN&#39;s DNS label, and the `oraclevcn.com` domain.
     * 
     */
    @Export(name="subnetDomainName", type=String.class, parameters={})
    private Output<String> subnetDomainName;

    /**
     * @return The subnet&#39;s domain name, which consists of the subnet&#39;s DNS label, the VCN&#39;s DNS label, and the `oraclevcn.com` domain.
     * 
     */
    public Output<String> subnetDomainName() {
        return this.subnetDomainName;
    }
    /**
     * The date and time the subnet was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    @Export(name="timeCreated", type=String.class, parameters={})
    private Output<String> timeCreated;

    /**
     * @return The date and time the subnet was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN to contain the subnet.
     * 
     */
    @Export(name="vcnId", type=String.class, parameters={})
    private Output<String> vcnId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN to contain the subnet.
     * 
     */
    public Output<String> vcnId() {
        return this.vcnId;
    }
    /**
     * The IP address of the virtual router.  Example: `10.0.14.1`
     * 
     */
    @Export(name="virtualRouterIp", type=String.class, parameters={})
    private Output<String> virtualRouterIp;

    /**
     * @return The IP address of the virtual router.  Example: `10.0.14.1`
     * 
     */
    public Output<String> virtualRouterIp() {
        return this.virtualRouterIp;
    }
    /**
     * The MAC address of the virtual router.  Example: `00:00:00:00:00:01`
     * 
     */
    @Export(name="virtualRouterMac", type=String.class, parameters={})
    private Output<String> virtualRouterMac;

    /**
     * @return The MAC address of the virtual router.  Example: `00:00:00:00:00:01`
     * 
     */
    public Output<String> virtualRouterMac() {
        return this.virtualRouterMac;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public Subnet(String name) {
        this(name, SubnetArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public Subnet(String name, SubnetArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public Subnet(String name, SubnetArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Core/subnet:Subnet", name, args == null ? SubnetArgs.Empty : args, makeResourceOptions(options, Codegen.empty()));
    }

    private Subnet(String name, Output<String> id, @Nullable SubnetState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Core/subnet:Subnet", name, state, makeResourceOptions(options, id));
    }

    private static com.pulumi.resources.CustomResourceOptions makeResourceOptions(@Nullable com.pulumi.resources.CustomResourceOptions options, @Nullable Output<String> id) {
        var defaultOptions = com.pulumi.resources.CustomResourceOptions.builder()
            .version(Utilities.getVersion())
            .build();
        return com.pulumi.resources.CustomResourceOptions.merge(defaultOptions, options, id);
    }

    /**
     * Get an existing Host resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state
     * @param options Optional settings to control the behavior of the CustomResource.
     */
    public static Subnet get(String name, Output<String> id, @Nullable SubnetState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new Subnet(name, id, state, options);
    }
}
