// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.NetworkFirewall.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.NetworkFirewall.outputs.GetNetworkFirewallPolicyUrlListsUrlListSummaryCollectionItemUrl;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetNetworkFirewallPolicyUrlListsUrlListSummaryCollectionItem {
    /**
     * @return Unique name identifier for the URL list.
     * 
     */
    private String name;
    /**
     * @return Unique Network Firewall Policy identifier
     * 
     */
    private String networkFirewallPolicyId;
    /**
     * @return OCID of the Network Firewall Policy this URL List belongs to.
     * 
     */
    private String parentResourceId;
    /**
     * @return Total count of URLs in the URL List
     * 
     */
    private Integer totalUrls;
    /**
     * @return List of urls.
     * 
     */
    private List<GetNetworkFirewallPolicyUrlListsUrlListSummaryCollectionItemUrl> urls;

    private GetNetworkFirewallPolicyUrlListsUrlListSummaryCollectionItem() {}
    /**
     * @return Unique name identifier for the URL list.
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
     * @return OCID of the Network Firewall Policy this URL List belongs to.
     * 
     */
    public String parentResourceId() {
        return this.parentResourceId;
    }
    /**
     * @return Total count of URLs in the URL List
     * 
     */
    public Integer totalUrls() {
        return this.totalUrls;
    }
    /**
     * @return List of urls.
     * 
     */
    public List<GetNetworkFirewallPolicyUrlListsUrlListSummaryCollectionItemUrl> urls() {
        return this.urls;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetNetworkFirewallPolicyUrlListsUrlListSummaryCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String name;
        private String networkFirewallPolicyId;
        private String parentResourceId;
        private Integer totalUrls;
        private List<GetNetworkFirewallPolicyUrlListsUrlListSummaryCollectionItemUrl> urls;
        public Builder() {}
        public Builder(GetNetworkFirewallPolicyUrlListsUrlListSummaryCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.name = defaults.name;
    	      this.networkFirewallPolicyId = defaults.networkFirewallPolicyId;
    	      this.parentResourceId = defaults.parentResourceId;
    	      this.totalUrls = defaults.totalUrls;
    	      this.urls = defaults.urls;
        }

        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("GetNetworkFirewallPolicyUrlListsUrlListSummaryCollectionItem", "name");
            }
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder networkFirewallPolicyId(String networkFirewallPolicyId) {
            if (networkFirewallPolicyId == null) {
              throw new MissingRequiredPropertyException("GetNetworkFirewallPolicyUrlListsUrlListSummaryCollectionItem", "networkFirewallPolicyId");
            }
            this.networkFirewallPolicyId = networkFirewallPolicyId;
            return this;
        }
        @CustomType.Setter
        public Builder parentResourceId(String parentResourceId) {
            if (parentResourceId == null) {
              throw new MissingRequiredPropertyException("GetNetworkFirewallPolicyUrlListsUrlListSummaryCollectionItem", "parentResourceId");
            }
            this.parentResourceId = parentResourceId;
            return this;
        }
        @CustomType.Setter
        public Builder totalUrls(Integer totalUrls) {
            if (totalUrls == null) {
              throw new MissingRequiredPropertyException("GetNetworkFirewallPolicyUrlListsUrlListSummaryCollectionItem", "totalUrls");
            }
            this.totalUrls = totalUrls;
            return this;
        }
        @CustomType.Setter
        public Builder urls(List<GetNetworkFirewallPolicyUrlListsUrlListSummaryCollectionItemUrl> urls) {
            if (urls == null) {
              throw new MissingRequiredPropertyException("GetNetworkFirewallPolicyUrlListsUrlListSummaryCollectionItem", "urls");
            }
            this.urls = urls;
            return this;
        }
        public Builder urls(GetNetworkFirewallPolicyUrlListsUrlListSummaryCollectionItemUrl... urls) {
            return urls(List.of(urls));
        }
        public GetNetworkFirewallPolicyUrlListsUrlListSummaryCollectionItem build() {
            final var _resultValue = new GetNetworkFirewallPolicyUrlListsUrlListSummaryCollectionItem();
            _resultValue.name = name;
            _resultValue.networkFirewallPolicyId = networkFirewallPolicyId;
            _resultValue.parentResourceId = parentResourceId;
            _resultValue.totalUrls = totalUrls;
            _resultValue.urls = urls;
            return _resultValue;
        }
    }
}
