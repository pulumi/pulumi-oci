// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.NetworkFirewall.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.NetworkFirewall.outputs.GetNetworkFirewallNatConfiguration;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetNetworkFirewallResult {
    /**
     * @return Availability Domain where Network Firewall instance is created. To get a list of availability domains for a tenancy, use the [ListAvailabilityDomains](https://docs.cloud.oracle.com/iaas/api/#/en/identity/20160918/AvailabilityDomain/ListAvailabilityDomains) operation. Example: `kIdk:PHX-AD-1`
     * 
     */
    private String availabilityDomain;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the Network Firewall.
     * 
     */
    private String compartmentId;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    private Map<String,String> definedTags;
    /**
     * @return A user-friendly name for the Network Firewall. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    private String displayName;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private Map<String,String> freeformTags;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Network Firewall resource.
     * 
     */
    private String id;
    /**
     * @return IPv4 address for the Network Firewall.
     * 
     */
    private String ipv4address;
    /**
     * @return IPv6 address for the Network Firewall.
     * 
     */
    private String ipv6address;
    /**
     * @return A message describing the current state in more detail. For example, it can be used to provide actionable information for a resource in &#39;FAILED&#39; state.
     * 
     */
    private String lifecycleDetails;
    /**
     * @return Nat Configuration response.
     * 
     */
    private List<GetNetworkFirewallNatConfiguration> natConfigurations;
    private String networkFirewallId;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Network Firewall Policy.
     * 
     */
    private String networkFirewallPolicyId;
    /**
     * @return An array of network security groups [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) associated with the Network Firewall.
     * 
     */
    private List<String> networkSecurityGroupIds;
    /**
     * @return The current state of the Network Firewall.
     * 
     */
    private String state;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet associated with the Network Firewall.
     * 
     */
    private String subnetId;
    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    private Map<String,String> systemTags;
    /**
     * @return The time at which the Network Firewall was created in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    private String timeCreated;
    /**
     * @return The time at which the Network Firewall was updated in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    private String timeUpdated;

    private GetNetworkFirewallResult() {}
    /**
     * @return Availability Domain where Network Firewall instance is created. To get a list of availability domains for a tenancy, use the [ListAvailabilityDomains](https://docs.cloud.oracle.com/iaas/api/#/en/identity/20160918/AvailabilityDomain/ListAvailabilityDomains) operation. Example: `kIdk:PHX-AD-1`
     * 
     */
    public String availabilityDomain() {
        return this.availabilityDomain;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the Network Firewall.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Map<String,String> definedTags() {
        return this.definedTags;
    }
    /**
     * @return A user-friendly name for the Network Firewall. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Map<String,String> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Network Firewall resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return IPv4 address for the Network Firewall.
     * 
     */
    public String ipv4address() {
        return this.ipv4address;
    }
    /**
     * @return IPv6 address for the Network Firewall.
     * 
     */
    public String ipv6address() {
        return this.ipv6address;
    }
    /**
     * @return A message describing the current state in more detail. For example, it can be used to provide actionable information for a resource in &#39;FAILED&#39; state.
     * 
     */
    public String lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * @return Nat Configuration response.
     * 
     */
    public List<GetNetworkFirewallNatConfiguration> natConfigurations() {
        return this.natConfigurations;
    }
    public String networkFirewallId() {
        return this.networkFirewallId;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Network Firewall Policy.
     * 
     */
    public String networkFirewallPolicyId() {
        return this.networkFirewallPolicyId;
    }
    /**
     * @return An array of network security groups [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) associated with the Network Firewall.
     * 
     */
    public List<String> networkSecurityGroupIds() {
        return this.networkSecurityGroupIds;
    }
    /**
     * @return The current state of the Network Firewall.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet associated with the Network Firewall.
     * 
     */
    public String subnetId() {
        return this.subnetId;
    }
    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Map<String,String> systemTags() {
        return this.systemTags;
    }
    /**
     * @return The time at which the Network Firewall was created in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The time at which the Network Firewall was updated in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetNetworkFirewallResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String availabilityDomain;
        private String compartmentId;
        private Map<String,String> definedTags;
        private String displayName;
        private Map<String,String> freeformTags;
        private String id;
        private String ipv4address;
        private String ipv6address;
        private String lifecycleDetails;
        private List<GetNetworkFirewallNatConfiguration> natConfigurations;
        private String networkFirewallId;
        private String networkFirewallPolicyId;
        private List<String> networkSecurityGroupIds;
        private String state;
        private String subnetId;
        private Map<String,String> systemTags;
        private String timeCreated;
        private String timeUpdated;
        public Builder() {}
        public Builder(GetNetworkFirewallResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.availabilityDomain = defaults.availabilityDomain;
    	      this.compartmentId = defaults.compartmentId;
    	      this.definedTags = defaults.definedTags;
    	      this.displayName = defaults.displayName;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.ipv4address = defaults.ipv4address;
    	      this.ipv6address = defaults.ipv6address;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.natConfigurations = defaults.natConfigurations;
    	      this.networkFirewallId = defaults.networkFirewallId;
    	      this.networkFirewallPolicyId = defaults.networkFirewallPolicyId;
    	      this.networkSecurityGroupIds = defaults.networkSecurityGroupIds;
    	      this.state = defaults.state;
    	      this.subnetId = defaults.subnetId;
    	      this.systemTags = defaults.systemTags;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
        }

        @CustomType.Setter
        public Builder availabilityDomain(String availabilityDomain) {
            if (availabilityDomain == null) {
              throw new MissingRequiredPropertyException("GetNetworkFirewallResult", "availabilityDomain");
            }
            this.availabilityDomain = availabilityDomain;
            return this;
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetNetworkFirewallResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,String> definedTags) {
            if (definedTags == null) {
              throw new MissingRequiredPropertyException("GetNetworkFirewallResult", "definedTags");
            }
            this.definedTags = definedTags;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetNetworkFirewallResult", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,String> freeformTags) {
            if (freeformTags == null) {
              throw new MissingRequiredPropertyException("GetNetworkFirewallResult", "freeformTags");
            }
            this.freeformTags = freeformTags;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetNetworkFirewallResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder ipv4address(String ipv4address) {
            if (ipv4address == null) {
              throw new MissingRequiredPropertyException("GetNetworkFirewallResult", "ipv4address");
            }
            this.ipv4address = ipv4address;
            return this;
        }
        @CustomType.Setter
        public Builder ipv6address(String ipv6address) {
            if (ipv6address == null) {
              throw new MissingRequiredPropertyException("GetNetworkFirewallResult", "ipv6address");
            }
            this.ipv6address = ipv6address;
            return this;
        }
        @CustomType.Setter
        public Builder lifecycleDetails(String lifecycleDetails) {
            if (lifecycleDetails == null) {
              throw new MissingRequiredPropertyException("GetNetworkFirewallResult", "lifecycleDetails");
            }
            this.lifecycleDetails = lifecycleDetails;
            return this;
        }
        @CustomType.Setter
        public Builder natConfigurations(List<GetNetworkFirewallNatConfiguration> natConfigurations) {
            if (natConfigurations == null) {
              throw new MissingRequiredPropertyException("GetNetworkFirewallResult", "natConfigurations");
            }
            this.natConfigurations = natConfigurations;
            return this;
        }
        public Builder natConfigurations(GetNetworkFirewallNatConfiguration... natConfigurations) {
            return natConfigurations(List.of(natConfigurations));
        }
        @CustomType.Setter
        public Builder networkFirewallId(String networkFirewallId) {
            if (networkFirewallId == null) {
              throw new MissingRequiredPropertyException("GetNetworkFirewallResult", "networkFirewallId");
            }
            this.networkFirewallId = networkFirewallId;
            return this;
        }
        @CustomType.Setter
        public Builder networkFirewallPolicyId(String networkFirewallPolicyId) {
            if (networkFirewallPolicyId == null) {
              throw new MissingRequiredPropertyException("GetNetworkFirewallResult", "networkFirewallPolicyId");
            }
            this.networkFirewallPolicyId = networkFirewallPolicyId;
            return this;
        }
        @CustomType.Setter
        public Builder networkSecurityGroupIds(List<String> networkSecurityGroupIds) {
            if (networkSecurityGroupIds == null) {
              throw new MissingRequiredPropertyException("GetNetworkFirewallResult", "networkSecurityGroupIds");
            }
            this.networkSecurityGroupIds = networkSecurityGroupIds;
            return this;
        }
        public Builder networkSecurityGroupIds(String... networkSecurityGroupIds) {
            return networkSecurityGroupIds(List.of(networkSecurityGroupIds));
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetNetworkFirewallResult", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder subnetId(String subnetId) {
            if (subnetId == null) {
              throw new MissingRequiredPropertyException("GetNetworkFirewallResult", "subnetId");
            }
            this.subnetId = subnetId;
            return this;
        }
        @CustomType.Setter
        public Builder systemTags(Map<String,String> systemTags) {
            if (systemTags == null) {
              throw new MissingRequiredPropertyException("GetNetworkFirewallResult", "systemTags");
            }
            this.systemTags = systemTags;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetNetworkFirewallResult", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(String timeUpdated) {
            if (timeUpdated == null) {
              throw new MissingRequiredPropertyException("GetNetworkFirewallResult", "timeUpdated");
            }
            this.timeUpdated = timeUpdated;
            return this;
        }
        public GetNetworkFirewallResult build() {
            final var _resultValue = new GetNetworkFirewallResult();
            _resultValue.availabilityDomain = availabilityDomain;
            _resultValue.compartmentId = compartmentId;
            _resultValue.definedTags = definedTags;
            _resultValue.displayName = displayName;
            _resultValue.freeformTags = freeformTags;
            _resultValue.id = id;
            _resultValue.ipv4address = ipv4address;
            _resultValue.ipv6address = ipv6address;
            _resultValue.lifecycleDetails = lifecycleDetails;
            _resultValue.natConfigurations = natConfigurations;
            _resultValue.networkFirewallId = networkFirewallId;
            _resultValue.networkFirewallPolicyId = networkFirewallPolicyId;
            _resultValue.networkSecurityGroupIds = networkSecurityGroupIds;
            _resultValue.state = state;
            _resultValue.subnetId = subnetId;
            _resultValue.systemTags = systemTags;
            _resultValue.timeCreated = timeCreated;
            _resultValue.timeUpdated = timeUpdated;
            return _resultValue;
        }
    }
}
