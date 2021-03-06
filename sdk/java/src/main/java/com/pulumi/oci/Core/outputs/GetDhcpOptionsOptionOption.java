// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDhcpOptionsOptionOption {
    /**
     * @return If you set `serverType` to `CustomDnsServer`, specify the IP address of at least one DNS server of your choice (three maximum).
     * 
     */
    private final List<String> customDnsServers;
    /**
     * @return A single search domain name according to [RFC 952](https://tools.ietf.org/html/rfc952) and [RFC 1123](https://tools.ietf.org/html/rfc1123). During a DNS query, the OS will append this search domain name to the value being queried.
     * 
     */
    private final List<String> searchDomainNames;
    /**
     * @return * **VcnLocal:** Reserved for future use.
     * * **VcnLocalPlusInternet:** Also referred to as &#34;Internet and VCN Resolver&#34;. Instances can resolve internet hostnames (no internet gateway is required), and can resolve hostnames of instances in the VCN. This is the default value in the default set of DHCP options in the VCN. For the Internet and VCN Resolver to work across the VCN, there must also be a DNS label set for the VCN, a DNS label set for each subnet, and a hostname for each instance. The Internet and VCN Resolver also enables reverse DNS lookup, which lets you determine the hostname corresponding to the private IP address. For more information, see [DNS in Your Virtual Cloud Network](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/dns.htm).
     * * **CustomDnsServer:** Instances use a DNS server of your choice (three maximum).
     * 
     */
    private final String serverType;
    /**
     * @return The specific DHCP option. Either `DomainNameServer` (for [DhcpDnsOption](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/DhcpDnsOption/)) or `SearchDomain` (for [DhcpSearchDomainOption](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/DhcpSearchDomainOption/)).
     * 
     */
    private final String type;

    @CustomType.Constructor
    private GetDhcpOptionsOptionOption(
        @CustomType.Parameter("customDnsServers") List<String> customDnsServers,
        @CustomType.Parameter("searchDomainNames") List<String> searchDomainNames,
        @CustomType.Parameter("serverType") String serverType,
        @CustomType.Parameter("type") String type) {
        this.customDnsServers = customDnsServers;
        this.searchDomainNames = searchDomainNames;
        this.serverType = serverType;
        this.type = type;
    }

    /**
     * @return If you set `serverType` to `CustomDnsServer`, specify the IP address of at least one DNS server of your choice (three maximum).
     * 
     */
    public List<String> customDnsServers() {
        return this.customDnsServers;
    }
    /**
     * @return A single search domain name according to [RFC 952](https://tools.ietf.org/html/rfc952) and [RFC 1123](https://tools.ietf.org/html/rfc1123). During a DNS query, the OS will append this search domain name to the value being queried.
     * 
     */
    public List<String> searchDomainNames() {
        return this.searchDomainNames;
    }
    /**
     * @return * **VcnLocal:** Reserved for future use.
     * * **VcnLocalPlusInternet:** Also referred to as &#34;Internet and VCN Resolver&#34;. Instances can resolve internet hostnames (no internet gateway is required), and can resolve hostnames of instances in the VCN. This is the default value in the default set of DHCP options in the VCN. For the Internet and VCN Resolver to work across the VCN, there must also be a DNS label set for the VCN, a DNS label set for each subnet, and a hostname for each instance. The Internet and VCN Resolver also enables reverse DNS lookup, which lets you determine the hostname corresponding to the private IP address. For more information, see [DNS in Your Virtual Cloud Network](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/dns.htm).
     * * **CustomDnsServer:** Instances use a DNS server of your choice (three maximum).
     * 
     */
    public String serverType() {
        return this.serverType;
    }
    /**
     * @return The specific DHCP option. Either `DomainNameServer` (for [DhcpDnsOption](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/DhcpDnsOption/)) or `SearchDomain` (for [DhcpSearchDomainOption](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/DhcpSearchDomainOption/)).
     * 
     */
    public String type() {
        return this.type;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDhcpOptionsOptionOption defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private List<String> customDnsServers;
        private List<String> searchDomainNames;
        private String serverType;
        private String type;

        public Builder() {
    	      // Empty
        }

        public Builder(GetDhcpOptionsOptionOption defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.customDnsServers = defaults.customDnsServers;
    	      this.searchDomainNames = defaults.searchDomainNames;
    	      this.serverType = defaults.serverType;
    	      this.type = defaults.type;
        }

        public Builder customDnsServers(List<String> customDnsServers) {
            this.customDnsServers = Objects.requireNonNull(customDnsServers);
            return this;
        }
        public Builder customDnsServers(String... customDnsServers) {
            return customDnsServers(List.of(customDnsServers));
        }
        public Builder searchDomainNames(List<String> searchDomainNames) {
            this.searchDomainNames = Objects.requireNonNull(searchDomainNames);
            return this;
        }
        public Builder searchDomainNames(String... searchDomainNames) {
            return searchDomainNames(List.of(searchDomainNames));
        }
        public Builder serverType(String serverType) {
            this.serverType = Objects.requireNonNull(serverType);
            return this;
        }
        public Builder type(String type) {
            this.type = Objects.requireNonNull(type);
            return this;
        }        public GetDhcpOptionsOptionOption build() {
            return new GetDhcpOptionsOptionOption(customDnsServers, searchDomainNames, serverType, type);
        }
    }
}
