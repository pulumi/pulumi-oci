// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.NetworkFirewall.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetNetworkFirewallPolicyDecryptionRulesDecryptionRuleSummaryCollectionItemPosition {
    /**
     * @return Identifier for rule after which this rule lies.
     * 
     */
    private @Nullable String afterRule;
    /**
     * @return Identifier for rule before which this rule lies.
     * 
     */
    private @Nullable String beforeRule;

    private GetNetworkFirewallPolicyDecryptionRulesDecryptionRuleSummaryCollectionItemPosition() {}
    /**
     * @return Identifier for rule after which this rule lies.
     * 
     */
    public Optional<String> afterRule() {
        return Optional.ofNullable(this.afterRule);
    }
    /**
     * @return Identifier for rule before which this rule lies.
     * 
     */
    public Optional<String> beforeRule() {
        return Optional.ofNullable(this.beforeRule);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetNetworkFirewallPolicyDecryptionRulesDecryptionRuleSummaryCollectionItemPosition defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String afterRule;
        private @Nullable String beforeRule;
        public Builder() {}
        public Builder(GetNetworkFirewallPolicyDecryptionRulesDecryptionRuleSummaryCollectionItemPosition defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.afterRule = defaults.afterRule;
    	      this.beforeRule = defaults.beforeRule;
        }

        @CustomType.Setter
        public Builder afterRule(@Nullable String afterRule) {
            this.afterRule = afterRule;
            return this;
        }
        @CustomType.Setter
        public Builder beforeRule(@Nullable String beforeRule) {
            this.beforeRule = beforeRule;
            return this;
        }
        public GetNetworkFirewallPolicyDecryptionRulesDecryptionRuleSummaryCollectionItemPosition build() {
            final var o = new GetNetworkFirewallPolicyDecryptionRulesDecryptionRuleSummaryCollectionItemPosition();
            o.afterRule = afterRule;
            o.beforeRule = beforeRule;
            return o;
        }
    }
}