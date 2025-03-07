// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class SubnetArgs extends com.pulumi.resources.ResourceArgs {

    public static final SubnetArgs Empty = new SubnetArgs();

    /**
     * Controls whether the subnet is regional or specific to an availability domain. Oracle recommends creating regional subnets because they&#39;re more flexible and make it easier to implement failover across availability domains. Originally, AD-specific subnets were the only kind available to use.
     * 
     * To create a regional subnet, omit this attribute. Then any resources later created in this subnet (such as a Compute instance) can be created in any availability domain in the region.
     * 
     * To instead create an AD-specific subnet, set this attribute to the availability domain you want this subnet to be in. Then any resources later created in this subnet can only be created in that availability domain.
     * 
     * Example: `Uocm:PHX-AD-1`
     * 
     */
    @Import(name="availabilityDomain")
    private @Nullable Output<String> availabilityDomain;

    /**
     * @return Controls whether the subnet is regional or specific to an availability domain. Oracle recommends creating regional subnets because they&#39;re more flexible and make it easier to implement failover across availability domains. Originally, AD-specific subnets were the only kind available to use.
     * 
     * To create a regional subnet, omit this attribute. Then any resources later created in this subnet (such as a Compute instance) can be created in any availability domain in the region.
     * 
     * To instead create an AD-specific subnet, set this attribute to the availability domain you want this subnet to be in. Then any resources later created in this subnet can only be created in that availability domain.
     * 
     * Example: `Uocm:PHX-AD-1`
     * 
     */
    public Optional<Output<String>> availabilityDomain() {
        return Optional.ofNullable(this.availabilityDomain);
    }

    /**
     * (Updatable) The CIDR IP address range of the subnet. The CIDR must maintain the following rules -
     * 
     * a. The CIDR block is valid and correctly formatted. b. The new range is within one of the parent VCN ranges.
     * 
     * Example: `10.0.1.0/24`
     * 
     */
    @Import(name="cidrBlock", required=true)
    private Output<String> cidrBlock;

    /**
     * @return (Updatable) The CIDR IP address range of the subnet. The CIDR must maintain the following rules -
     * 
     * a. The CIDR block is valid and correctly formatted. b. The new range is within one of the parent VCN ranges.
     * 
     * Example: `10.0.1.0/24`
     * 
     */
    public Output<String> cidrBlock() {
        return this.cidrBlock;
    }

    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to contain the subnet.
     * 
     */
    @Import(name="compartmentId", required=true)
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
    @Import(name="definedTags")
    private @Nullable Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the set of DHCP options the subnet will use. If you don&#39;t provide a value, the subnet uses the VCN&#39;s default set of DHCP options.
     * 
     */
    @Import(name="dhcpOptionsId")
    private @Nullable Output<String> dhcpOptionsId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the set of DHCP options the subnet will use. If you don&#39;t provide a value, the subnet uses the VCN&#39;s default set of DHCP options.
     * 
     */
    public Optional<Output<String>> dhcpOptionsId() {
        return Optional.ofNullable(this.dhcpOptionsId);
    }

    /**
     * (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * A DNS label for the subnet, used in conjunction with the VNIC&#39;s hostname and VCN&#39;s DNS label to form a fully qualified domain name (FQDN) for each VNIC within this subnet (for example, `bminstance1.subnet123.vcn1.oraclevcn.com`). Must be an alphanumeric string that begins with a letter and is unique within the VCN. The value cannot be changed.
     * 
     * This value must be set if you want to use the Internet and VCN Resolver to resolve the hostnames of instances in the subnet. It can only be set if the VCN itself was created with a DNS label.
     * 
     * For more information, see [DNS in Your Virtual Cloud Network](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/dns.htm).
     * 
     * Example: `subnet123`
     * 
     */
    @Import(name="dnsLabel")
    private @Nullable Output<String> dnsLabel;

    /**
     * @return A DNS label for the subnet, used in conjunction with the VNIC&#39;s hostname and VCN&#39;s DNS label to form a fully qualified domain name (FQDN) for each VNIC within this subnet (for example, `bminstance1.subnet123.vcn1.oraclevcn.com`). Must be an alphanumeric string that begins with a letter and is unique within the VCN. The value cannot be changed.
     * 
     * This value must be set if you want to use the Internet and VCN Resolver to resolve the hostnames of instances in the subnet. It can only be set if the VCN itself was created with a DNS label.
     * 
     * For more information, see [DNS in Your Virtual Cloud Network](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/dns.htm).
     * 
     * Example: `subnet123`
     * 
     */
    public Optional<Output<String>> dnsLabel() {
        return Optional.ofNullable(this.dnsLabel);
    }

    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * (Updatable) Use this to enable IPv6 addressing for this subnet. The VCN must be enabled for IPv6. You can&#39;t change this subnet characteristic later. All subnets are /64 in size. The subnet portion of the IPv6 address is the fourth hextet from the left (1111 in the following example).
     * 
     * For important details about IPv6 addressing in a VCN, see [IPv6 Addresses](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/ipv6.htm).
     * 
     * Example: `2001:0db8:0123:1111::/64`
     * 
     */
    @Import(name="ipv6cidrBlock")
    private @Nullable Output<String> ipv6cidrBlock;

    /**
     * @return (Updatable) Use this to enable IPv6 addressing for this subnet. The VCN must be enabled for IPv6. You can&#39;t change this subnet characteristic later. All subnets are /64 in size. The subnet portion of the IPv6 address is the fourth hextet from the left (1111 in the following example).
     * 
     * For important details about IPv6 addressing in a VCN, see [IPv6 Addresses](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/ipv6.htm).
     * 
     * Example: `2001:0db8:0123:1111::/64`
     * 
     */
    public Optional<Output<String>> ipv6cidrBlock() {
        return Optional.ofNullable(this.ipv6cidrBlock);
    }

    /**
     * (Updatable) The list of all IPv6 prefixes (Oracle allocated IPv6 GUA, ULA or private IPv6 prefixes, BYOIPv6 prefixes) for the subnet that meets the following criteria:
     * * The prefixes must be valid.
     * * Multiple prefixes must not overlap each other or the on-premises network prefix.
     * * The number of prefixes must not exceed the limit of IPv6 prefixes allowed to a subnet.
     * 
     */
    @Import(name="ipv6cidrBlocks")
    private @Nullable Output<List<String>> ipv6cidrBlocks;

    /**
     * @return (Updatable) The list of all IPv6 prefixes (Oracle allocated IPv6 GUA, ULA or private IPv6 prefixes, BYOIPv6 prefixes) for the subnet that meets the following criteria:
     * * The prefixes must be valid.
     * * Multiple prefixes must not overlap each other or the on-premises network prefix.
     * * The number of prefixes must not exceed the limit of IPv6 prefixes allowed to a subnet.
     * 
     */
    public Optional<Output<List<String>>> ipv6cidrBlocks() {
        return Optional.ofNullable(this.ipv6cidrBlocks);
    }

    /**
     * Whether to disallow ingress internet traffic to VNICs within this subnet. Defaults to false.
     * 
     * For IPv6, if `prohibitInternetIngress` is set to `true`, internet access is not allowed for any IPv6s assigned to VNICs in the subnet. Otherwise, ingress internet traffic is allowed by default.
     * 
     * `prohibitPublicIpOnVnic` will be set to the value of `prohibitInternetIngress` to dictate IPv4 behavior in this subnet. Only one or the other flag should be specified.
     * 
     * Example: `true`
     * 
     */
    @Import(name="prohibitInternetIngress")
    private @Nullable Output<Boolean> prohibitInternetIngress;

    /**
     * @return Whether to disallow ingress internet traffic to VNICs within this subnet. Defaults to false.
     * 
     * For IPv6, if `prohibitInternetIngress` is set to `true`, internet access is not allowed for any IPv6s assigned to VNICs in the subnet. Otherwise, ingress internet traffic is allowed by default.
     * 
     * `prohibitPublicIpOnVnic` will be set to the value of `prohibitInternetIngress` to dictate IPv4 behavior in this subnet. Only one or the other flag should be specified.
     * 
     * Example: `true`
     * 
     */
    public Optional<Output<Boolean>> prohibitInternetIngress() {
        return Optional.ofNullable(this.prohibitInternetIngress);
    }

    /**
     * Whether VNICs within this subnet can have public IP addresses. Defaults to false, which means VNICs created in this subnet will automatically be assigned public IP addresses unless specified otherwise during instance launch or VNIC creation (with the `assignPublicIp` flag in [CreateVnicDetails](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/CreateVnicDetails/)). If `prohibitPublicIpOnVnic` is set to true, VNICs created in this subnet cannot have public IP addresses (that is, it&#39;s a private subnet).
     * 
     * If you intend to use an IPv6 prefix, you should use the flag `prohibitInternetIngress` to specify ingress internet traffic behavior of the subnet.
     * 
     * Example: `true`
     * 
     */
    @Import(name="prohibitPublicIpOnVnic")
    private @Nullable Output<Boolean> prohibitPublicIpOnVnic;

    /**
     * @return Whether VNICs within this subnet can have public IP addresses. Defaults to false, which means VNICs created in this subnet will automatically be assigned public IP addresses unless specified otherwise during instance launch or VNIC creation (with the `assignPublicIp` flag in [CreateVnicDetails](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/CreateVnicDetails/)). If `prohibitPublicIpOnVnic` is set to true, VNICs created in this subnet cannot have public IP addresses (that is, it&#39;s a private subnet).
     * 
     * If you intend to use an IPv6 prefix, you should use the flag `prohibitInternetIngress` to specify ingress internet traffic behavior of the subnet.
     * 
     * Example: `true`
     * 
     */
    public Optional<Output<Boolean>> prohibitPublicIpOnVnic() {
        return Optional.ofNullable(this.prohibitPublicIpOnVnic);
    }

    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the route table the subnet will use. If you don&#39;t provide a value, the subnet uses the VCN&#39;s default route table.
     * 
     */
    @Import(name="routeTableId")
    private @Nullable Output<String> routeTableId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the route table the subnet will use. If you don&#39;t provide a value, the subnet uses the VCN&#39;s default route table.
     * 
     */
    public Optional<Output<String>> routeTableId() {
        return Optional.ofNullable(this.routeTableId);
    }

    /**
     * (Updatable) The OCIDs of the security list or lists the subnet will use. If you don&#39;t provide a value, the subnet uses the VCN&#39;s default security list. Remember that security lists are associated *with the subnet*, but the rules are applied to the individual VNICs in the subnet.
     * 
     */
    @Import(name="securityListIds")
    private @Nullable Output<List<String>> securityListIds;

    /**
     * @return (Updatable) The OCIDs of the security list or lists the subnet will use. If you don&#39;t provide a value, the subnet uses the VCN&#39;s default security list. Remember that security lists are associated *with the subnet*, but the rules are applied to the individual VNICs in the subnet.
     * 
     */
    public Optional<Output<List<String>>> securityListIds() {
        return Optional.ofNullable(this.securityListIds);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN to contain the subnet.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="vcnId", required=true)
    private Output<String> vcnId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN to contain the subnet.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> vcnId() {
        return this.vcnId;
    }

    private SubnetArgs() {}

    private SubnetArgs(SubnetArgs $) {
        this.availabilityDomain = $.availabilityDomain;
        this.cidrBlock = $.cidrBlock;
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.dhcpOptionsId = $.dhcpOptionsId;
        this.displayName = $.displayName;
        this.dnsLabel = $.dnsLabel;
        this.freeformTags = $.freeformTags;
        this.ipv6cidrBlock = $.ipv6cidrBlock;
        this.ipv6cidrBlocks = $.ipv6cidrBlocks;
        this.prohibitInternetIngress = $.prohibitInternetIngress;
        this.prohibitPublicIpOnVnic = $.prohibitPublicIpOnVnic;
        this.routeTableId = $.routeTableId;
        this.securityListIds = $.securityListIds;
        this.vcnId = $.vcnId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(SubnetArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private SubnetArgs $;

        public Builder() {
            $ = new SubnetArgs();
        }

        public Builder(SubnetArgs defaults) {
            $ = new SubnetArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param availabilityDomain Controls whether the subnet is regional or specific to an availability domain. Oracle recommends creating regional subnets because they&#39;re more flexible and make it easier to implement failover across availability domains. Originally, AD-specific subnets were the only kind available to use.
         * 
         * To create a regional subnet, omit this attribute. Then any resources later created in this subnet (such as a Compute instance) can be created in any availability domain in the region.
         * 
         * To instead create an AD-specific subnet, set this attribute to the availability domain you want this subnet to be in. Then any resources later created in this subnet can only be created in that availability domain.
         * 
         * Example: `Uocm:PHX-AD-1`
         * 
         * @return builder
         * 
         */
        public Builder availabilityDomain(@Nullable Output<String> availabilityDomain) {
            $.availabilityDomain = availabilityDomain;
            return this;
        }

        /**
         * @param availabilityDomain Controls whether the subnet is regional or specific to an availability domain. Oracle recommends creating regional subnets because they&#39;re more flexible and make it easier to implement failover across availability domains. Originally, AD-specific subnets were the only kind available to use.
         * 
         * To create a regional subnet, omit this attribute. Then any resources later created in this subnet (such as a Compute instance) can be created in any availability domain in the region.
         * 
         * To instead create an AD-specific subnet, set this attribute to the availability domain you want this subnet to be in. Then any resources later created in this subnet can only be created in that availability domain.
         * 
         * Example: `Uocm:PHX-AD-1`
         * 
         * @return builder
         * 
         */
        public Builder availabilityDomain(String availabilityDomain) {
            return availabilityDomain(Output.of(availabilityDomain));
        }

        /**
         * @param cidrBlock (Updatable) The CIDR IP address range of the subnet. The CIDR must maintain the following rules -
         * 
         * a. The CIDR block is valid and correctly formatted. b. The new range is within one of the parent VCN ranges.
         * 
         * Example: `10.0.1.0/24`
         * 
         * @return builder
         * 
         */
        public Builder cidrBlock(Output<String> cidrBlock) {
            $.cidrBlock = cidrBlock;
            return this;
        }

        /**
         * @param cidrBlock (Updatable) The CIDR IP address range of the subnet. The CIDR must maintain the following rules -
         * 
         * a. The CIDR block is valid and correctly formatted. b. The new range is within one of the parent VCN ranges.
         * 
         * Example: `10.0.1.0/24`
         * 
         * @return builder
         * 
         */
        public Builder cidrBlock(String cidrBlock) {
            return cidrBlock(Output.of(cidrBlock));
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to contain the subnet.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to contain the subnet.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,String>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,String> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param dhcpOptionsId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the set of DHCP options the subnet will use. If you don&#39;t provide a value, the subnet uses the VCN&#39;s default set of DHCP options.
         * 
         * @return builder
         * 
         */
        public Builder dhcpOptionsId(@Nullable Output<String> dhcpOptionsId) {
            $.dhcpOptionsId = dhcpOptionsId;
            return this;
        }

        /**
         * @param dhcpOptionsId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the set of DHCP options the subnet will use. If you don&#39;t provide a value, the subnet uses the VCN&#39;s default set of DHCP options.
         * 
         * @return builder
         * 
         */
        public Builder dhcpOptionsId(String dhcpOptionsId) {
            return dhcpOptionsId(Output.of(dhcpOptionsId));
        }

        /**
         * @param displayName (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param dnsLabel A DNS label for the subnet, used in conjunction with the VNIC&#39;s hostname and VCN&#39;s DNS label to form a fully qualified domain name (FQDN) for each VNIC within this subnet (for example, `bminstance1.subnet123.vcn1.oraclevcn.com`). Must be an alphanumeric string that begins with a letter and is unique within the VCN. The value cannot be changed.
         * 
         * This value must be set if you want to use the Internet and VCN Resolver to resolve the hostnames of instances in the subnet. It can only be set if the VCN itself was created with a DNS label.
         * 
         * For more information, see [DNS in Your Virtual Cloud Network](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/dns.htm).
         * 
         * Example: `subnet123`
         * 
         * @return builder
         * 
         */
        public Builder dnsLabel(@Nullable Output<String> dnsLabel) {
            $.dnsLabel = dnsLabel;
            return this;
        }

        /**
         * @param dnsLabel A DNS label for the subnet, used in conjunction with the VNIC&#39;s hostname and VCN&#39;s DNS label to form a fully qualified domain name (FQDN) for each VNIC within this subnet (for example, `bminstance1.subnet123.vcn1.oraclevcn.com`). Must be an alphanumeric string that begins with a letter and is unique within the VCN. The value cannot be changed.
         * 
         * This value must be set if you want to use the Internet and VCN Resolver to resolve the hostnames of instances in the subnet. It can only be set if the VCN itself was created with a DNS label.
         * 
         * For more information, see [DNS in Your Virtual Cloud Network](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/dns.htm).
         * 
         * Example: `subnet123`
         * 
         * @return builder
         * 
         */
        public Builder dnsLabel(String dnsLabel) {
            return dnsLabel(Output.of(dnsLabel));
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,String>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,String> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param ipv6cidrBlock (Updatable) Use this to enable IPv6 addressing for this subnet. The VCN must be enabled for IPv6. You can&#39;t change this subnet characteristic later. All subnets are /64 in size. The subnet portion of the IPv6 address is the fourth hextet from the left (1111 in the following example).
         * 
         * For important details about IPv6 addressing in a VCN, see [IPv6 Addresses](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/ipv6.htm).
         * 
         * Example: `2001:0db8:0123:1111::/64`
         * 
         * @return builder
         * 
         */
        public Builder ipv6cidrBlock(@Nullable Output<String> ipv6cidrBlock) {
            $.ipv6cidrBlock = ipv6cidrBlock;
            return this;
        }

        /**
         * @param ipv6cidrBlock (Updatable) Use this to enable IPv6 addressing for this subnet. The VCN must be enabled for IPv6. You can&#39;t change this subnet characteristic later. All subnets are /64 in size. The subnet portion of the IPv6 address is the fourth hextet from the left (1111 in the following example).
         * 
         * For important details about IPv6 addressing in a VCN, see [IPv6 Addresses](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/ipv6.htm).
         * 
         * Example: `2001:0db8:0123:1111::/64`
         * 
         * @return builder
         * 
         */
        public Builder ipv6cidrBlock(String ipv6cidrBlock) {
            return ipv6cidrBlock(Output.of(ipv6cidrBlock));
        }

        /**
         * @param ipv6cidrBlocks (Updatable) The list of all IPv6 prefixes (Oracle allocated IPv6 GUA, ULA or private IPv6 prefixes, BYOIPv6 prefixes) for the subnet that meets the following criteria:
         * * The prefixes must be valid.
         * * Multiple prefixes must not overlap each other or the on-premises network prefix.
         * * The number of prefixes must not exceed the limit of IPv6 prefixes allowed to a subnet.
         * 
         * @return builder
         * 
         */
        public Builder ipv6cidrBlocks(@Nullable Output<List<String>> ipv6cidrBlocks) {
            $.ipv6cidrBlocks = ipv6cidrBlocks;
            return this;
        }

        /**
         * @param ipv6cidrBlocks (Updatable) The list of all IPv6 prefixes (Oracle allocated IPv6 GUA, ULA or private IPv6 prefixes, BYOIPv6 prefixes) for the subnet that meets the following criteria:
         * * The prefixes must be valid.
         * * Multiple prefixes must not overlap each other or the on-premises network prefix.
         * * The number of prefixes must not exceed the limit of IPv6 prefixes allowed to a subnet.
         * 
         * @return builder
         * 
         */
        public Builder ipv6cidrBlocks(List<String> ipv6cidrBlocks) {
            return ipv6cidrBlocks(Output.of(ipv6cidrBlocks));
        }

        /**
         * @param ipv6cidrBlocks (Updatable) The list of all IPv6 prefixes (Oracle allocated IPv6 GUA, ULA or private IPv6 prefixes, BYOIPv6 prefixes) for the subnet that meets the following criteria:
         * * The prefixes must be valid.
         * * Multiple prefixes must not overlap each other or the on-premises network prefix.
         * * The number of prefixes must not exceed the limit of IPv6 prefixes allowed to a subnet.
         * 
         * @return builder
         * 
         */
        public Builder ipv6cidrBlocks(String... ipv6cidrBlocks) {
            return ipv6cidrBlocks(List.of(ipv6cidrBlocks));
        }

        /**
         * @param prohibitInternetIngress Whether to disallow ingress internet traffic to VNICs within this subnet. Defaults to false.
         * 
         * For IPv6, if `prohibitInternetIngress` is set to `true`, internet access is not allowed for any IPv6s assigned to VNICs in the subnet. Otherwise, ingress internet traffic is allowed by default.
         * 
         * `prohibitPublicIpOnVnic` will be set to the value of `prohibitInternetIngress` to dictate IPv4 behavior in this subnet. Only one or the other flag should be specified.
         * 
         * Example: `true`
         * 
         * @return builder
         * 
         */
        public Builder prohibitInternetIngress(@Nullable Output<Boolean> prohibitInternetIngress) {
            $.prohibitInternetIngress = prohibitInternetIngress;
            return this;
        }

        /**
         * @param prohibitInternetIngress Whether to disallow ingress internet traffic to VNICs within this subnet. Defaults to false.
         * 
         * For IPv6, if `prohibitInternetIngress` is set to `true`, internet access is not allowed for any IPv6s assigned to VNICs in the subnet. Otherwise, ingress internet traffic is allowed by default.
         * 
         * `prohibitPublicIpOnVnic` will be set to the value of `prohibitInternetIngress` to dictate IPv4 behavior in this subnet. Only one or the other flag should be specified.
         * 
         * Example: `true`
         * 
         * @return builder
         * 
         */
        public Builder prohibitInternetIngress(Boolean prohibitInternetIngress) {
            return prohibitInternetIngress(Output.of(prohibitInternetIngress));
        }

        /**
         * @param prohibitPublicIpOnVnic Whether VNICs within this subnet can have public IP addresses. Defaults to false, which means VNICs created in this subnet will automatically be assigned public IP addresses unless specified otherwise during instance launch or VNIC creation (with the `assignPublicIp` flag in [CreateVnicDetails](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/CreateVnicDetails/)). If `prohibitPublicIpOnVnic` is set to true, VNICs created in this subnet cannot have public IP addresses (that is, it&#39;s a private subnet).
         * 
         * If you intend to use an IPv6 prefix, you should use the flag `prohibitInternetIngress` to specify ingress internet traffic behavior of the subnet.
         * 
         * Example: `true`
         * 
         * @return builder
         * 
         */
        public Builder prohibitPublicIpOnVnic(@Nullable Output<Boolean> prohibitPublicIpOnVnic) {
            $.prohibitPublicIpOnVnic = prohibitPublicIpOnVnic;
            return this;
        }

        /**
         * @param prohibitPublicIpOnVnic Whether VNICs within this subnet can have public IP addresses. Defaults to false, which means VNICs created in this subnet will automatically be assigned public IP addresses unless specified otherwise during instance launch or VNIC creation (with the `assignPublicIp` flag in [CreateVnicDetails](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/CreateVnicDetails/)). If `prohibitPublicIpOnVnic` is set to true, VNICs created in this subnet cannot have public IP addresses (that is, it&#39;s a private subnet).
         * 
         * If you intend to use an IPv6 prefix, you should use the flag `prohibitInternetIngress` to specify ingress internet traffic behavior of the subnet.
         * 
         * Example: `true`
         * 
         * @return builder
         * 
         */
        public Builder prohibitPublicIpOnVnic(Boolean prohibitPublicIpOnVnic) {
            return prohibitPublicIpOnVnic(Output.of(prohibitPublicIpOnVnic));
        }

        /**
         * @param routeTableId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the route table the subnet will use. If you don&#39;t provide a value, the subnet uses the VCN&#39;s default route table.
         * 
         * @return builder
         * 
         */
        public Builder routeTableId(@Nullable Output<String> routeTableId) {
            $.routeTableId = routeTableId;
            return this;
        }

        /**
         * @param routeTableId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the route table the subnet will use. If you don&#39;t provide a value, the subnet uses the VCN&#39;s default route table.
         * 
         * @return builder
         * 
         */
        public Builder routeTableId(String routeTableId) {
            return routeTableId(Output.of(routeTableId));
        }

        /**
         * @param securityListIds (Updatable) The OCIDs of the security list or lists the subnet will use. If you don&#39;t provide a value, the subnet uses the VCN&#39;s default security list. Remember that security lists are associated *with the subnet*, but the rules are applied to the individual VNICs in the subnet.
         * 
         * @return builder
         * 
         */
        public Builder securityListIds(@Nullable Output<List<String>> securityListIds) {
            $.securityListIds = securityListIds;
            return this;
        }

        /**
         * @param securityListIds (Updatable) The OCIDs of the security list or lists the subnet will use. If you don&#39;t provide a value, the subnet uses the VCN&#39;s default security list. Remember that security lists are associated *with the subnet*, but the rules are applied to the individual VNICs in the subnet.
         * 
         * @return builder
         * 
         */
        public Builder securityListIds(List<String> securityListIds) {
            return securityListIds(Output.of(securityListIds));
        }

        /**
         * @param securityListIds (Updatable) The OCIDs of the security list or lists the subnet will use. If you don&#39;t provide a value, the subnet uses the VCN&#39;s default security list. Remember that security lists are associated *with the subnet*, but the rules are applied to the individual VNICs in the subnet.
         * 
         * @return builder
         * 
         */
        public Builder securityListIds(String... securityListIds) {
            return securityListIds(List.of(securityListIds));
        }

        /**
         * @param vcnId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN to contain the subnet.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder vcnId(Output<String> vcnId) {
            $.vcnId = vcnId;
            return this;
        }

        /**
         * @param vcnId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN to contain the subnet.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder vcnId(String vcnId) {
            return vcnId(Output.of(vcnId));
        }

        public SubnetArgs build() {
            if ($.cidrBlock == null) {
                throw new MissingRequiredPropertyException("SubnetArgs", "cidrBlock");
            }
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("SubnetArgs", "compartmentId");
            }
            if ($.vcnId == null) {
                throw new MissingRequiredPropertyException("SubnetArgs", "vcnId");
            }
            return $;
        }
    }

}
