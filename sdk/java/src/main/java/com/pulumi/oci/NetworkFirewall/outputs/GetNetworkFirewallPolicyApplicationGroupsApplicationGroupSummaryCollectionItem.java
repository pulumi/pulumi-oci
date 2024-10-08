// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.NetworkFirewall.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetNetworkFirewallPolicyApplicationGroupsApplicationGroupSummaryCollectionItem {
    /**
     * @return List of apps in the group.
     * 
     */
    private List<String> apps;
    /**
     * @return Name of the application Group.
     * 
     */
    private String name;
    /**
     * @return Unique Network Firewall Policy identifier
     * 
     */
    private String networkFirewallPolicyId;
    /**
     * @return OCID of the Network Firewall Policy this application group belongs to.
     * 
     */
    private String parentResourceId;
    /**
     * @return Count of total applications in the given application group.
     * 
     */
    private Integer totalApps;

    private GetNetworkFirewallPolicyApplicationGroupsApplicationGroupSummaryCollectionItem() {}
    /**
     * @return List of apps in the group.
     * 
     */
    public List<String> apps() {
        return this.apps;
    }
    /**
     * @return Name of the application Group.
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
     * @return OCID of the Network Firewall Policy this application group belongs to.
     * 
     */
    public String parentResourceId() {
        return this.parentResourceId;
    }
    /**
     * @return Count of total applications in the given application group.
     * 
     */
    public Integer totalApps() {
        return this.totalApps;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetNetworkFirewallPolicyApplicationGroupsApplicationGroupSummaryCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<String> apps;
        private String name;
        private String networkFirewallPolicyId;
        private String parentResourceId;
        private Integer totalApps;
        public Builder() {}
        public Builder(GetNetworkFirewallPolicyApplicationGroupsApplicationGroupSummaryCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.apps = defaults.apps;
    	      this.name = defaults.name;
    	      this.networkFirewallPolicyId = defaults.networkFirewallPolicyId;
    	      this.parentResourceId = defaults.parentResourceId;
    	      this.totalApps = defaults.totalApps;
        }

        @CustomType.Setter
        public Builder apps(List<String> apps) {
            if (apps == null) {
              throw new MissingRequiredPropertyException("GetNetworkFirewallPolicyApplicationGroupsApplicationGroupSummaryCollectionItem", "apps");
            }
            this.apps = apps;
            return this;
        }
        public Builder apps(String... apps) {
            return apps(List.of(apps));
        }
        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("GetNetworkFirewallPolicyApplicationGroupsApplicationGroupSummaryCollectionItem", "name");
            }
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder networkFirewallPolicyId(String networkFirewallPolicyId) {
            if (networkFirewallPolicyId == null) {
              throw new MissingRequiredPropertyException("GetNetworkFirewallPolicyApplicationGroupsApplicationGroupSummaryCollectionItem", "networkFirewallPolicyId");
            }
            this.networkFirewallPolicyId = networkFirewallPolicyId;
            return this;
        }
        @CustomType.Setter
        public Builder parentResourceId(String parentResourceId) {
            if (parentResourceId == null) {
              throw new MissingRequiredPropertyException("GetNetworkFirewallPolicyApplicationGroupsApplicationGroupSummaryCollectionItem", "parentResourceId");
            }
            this.parentResourceId = parentResourceId;
            return this;
        }
        @CustomType.Setter
        public Builder totalApps(Integer totalApps) {
            if (totalApps == null) {
              throw new MissingRequiredPropertyException("GetNetworkFirewallPolicyApplicationGroupsApplicationGroupSummaryCollectionItem", "totalApps");
            }
            this.totalApps = totalApps;
            return this;
        }
        public GetNetworkFirewallPolicyApplicationGroupsApplicationGroupSummaryCollectionItem build() {
            final var _resultValue = new GetNetworkFirewallPolicyApplicationGroupsApplicationGroupSummaryCollectionItem();
            _resultValue.apps = apps;
            _resultValue.name = name;
            _resultValue.networkFirewallPolicyId = networkFirewallPolicyId;
            _resultValue.parentResourceId = parentResourceId;
            _resultValue.totalApps = totalApps;
            return _resultValue;
        }
    }
}
