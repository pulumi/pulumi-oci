// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.NetworkFirewall.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetNetworkFirewallPolicyAddressListsAddressListSummaryCollectionItem {
    /**
     * @return List of addresses.
     * 
     */
    private List<String> addresses;
    /**
     * @return Unique name to identify the group of addresses to be used in the policy rules.
     * 
     */
    private String name;
    /**
     * @return Unique Network Firewall Policy identifier
     * 
     */
    private String networkFirewallPolicyId;
    /**
     * @return OCID of the Network Firewall Policy this Address List belongs to.
     * 
     */
    private String parentResourceId;
    /**
     * @return Count of total Addresses in the AddressList
     * 
     */
    private Integer totalAddresses;
    /**
     * @return Type of address list.
     * 
     */
    private String type;

    private GetNetworkFirewallPolicyAddressListsAddressListSummaryCollectionItem() {}
    /**
     * @return List of addresses.
     * 
     */
    public List<String> addresses() {
        return this.addresses;
    }
    /**
     * @return Unique name to identify the group of addresses to be used in the policy rules.
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return Unique Network Firewall Policy identifier
     * 
     */
    public String networkFirewallPolicyId() {
        return this.networkFirewallPolicyId;
    }
    /**
     * @return OCID of the Network Firewall Policy this Address List belongs to.
     * 
     */
    public String parentResourceId() {
        return this.parentResourceId;
    }
    /**
     * @return Count of total Addresses in the AddressList
     * 
     */
    public Integer totalAddresses() {
        return this.totalAddresses;
    }
    /**
     * @return Type of address list.
     * 
     */
    public String type() {
        return this.type;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetNetworkFirewallPolicyAddressListsAddressListSummaryCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<String> addresses;
        private String name;
        private String networkFirewallPolicyId;
        private String parentResourceId;
        private Integer totalAddresses;
        private String type;
        public Builder() {}
        public Builder(GetNetworkFirewallPolicyAddressListsAddressListSummaryCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.addresses = defaults.addresses;
    	      this.name = defaults.name;
    	      this.networkFirewallPolicyId = defaults.networkFirewallPolicyId;
    	      this.parentResourceId = defaults.parentResourceId;
    	      this.totalAddresses = defaults.totalAddresses;
    	      this.type = defaults.type;
        }

        @CustomType.Setter
        public Builder addresses(List<String> addresses) {
            this.addresses = Objects.requireNonNull(addresses);
            return this;
        }
        public Builder addresses(String... addresses) {
            return addresses(List.of(addresses));
        }
        @CustomType.Setter
        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }
        @CustomType.Setter
        public Builder networkFirewallPolicyId(String networkFirewallPolicyId) {
            this.networkFirewallPolicyId = Objects.requireNonNull(networkFirewallPolicyId);
            return this;
        }
        @CustomType.Setter
        public Builder parentResourceId(String parentResourceId) {
            this.parentResourceId = Objects.requireNonNull(parentResourceId);
            return this;
        }
        @CustomType.Setter
        public Builder totalAddresses(Integer totalAddresses) {
            this.totalAddresses = Objects.requireNonNull(totalAddresses);
            return this;
        }
        @CustomType.Setter
        public Builder type(String type) {
            this.type = Objects.requireNonNull(type);
            return this;
        }
        public GetNetworkFirewallPolicyAddressListsAddressListSummaryCollectionItem build() {
            final var o = new GetNetworkFirewallPolicyAddressListsAddressListSummaryCollectionItem();
            o.addresses = addresses;
            o.name = name;
            o.networkFirewallPolicyId = networkFirewallPolicyId;
            o.parentResourceId = parentResourceId;
            o.totalAddresses = totalAddresses;
            o.type = type;
            return o;
        }
    }
}