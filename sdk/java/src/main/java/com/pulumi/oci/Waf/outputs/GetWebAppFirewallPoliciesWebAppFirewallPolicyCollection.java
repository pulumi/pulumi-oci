// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Waf.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Waf.outputs.GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetWebAppFirewallPoliciesWebAppFirewallPolicyCollection {
    private List<GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItem> items;

    private GetWebAppFirewallPoliciesWebAppFirewallPolicyCollection() {}
    public List<GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetWebAppFirewallPoliciesWebAppFirewallPolicyCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItem> items;
        public Builder() {}
        public Builder(GetWebAppFirewallPoliciesWebAppFirewallPolicyCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItem... items) {
            return items(List.of(items));
        }
        public GetWebAppFirewallPoliciesWebAppFirewallPolicyCollection build() {
            final var o = new GetWebAppFirewallPoliciesWebAppFirewallPolicyCollection();
            o.items = items;
            return o;
        }
    }
}