// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.NetworkFirewall.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class NetworkFirewallPolicyUrlListUrlListValue {
    /**
     * @return (Updatable) URL lists to allow or deny traffic to a group of URLs. You can include a maximum of 25 URLs in each list.
     * 
     */
    private @Nullable String pattern;
    /**
     * @return (Updatable) Type of the url lists based on the policy
     * 
     */
    private String type;

    private NetworkFirewallPolicyUrlListUrlListValue() {}
    /**
     * @return (Updatable) URL lists to allow or deny traffic to a group of URLs. You can include a maximum of 25 URLs in each list.
     * 
     */
    public Optional<String> pattern() {
        return Optional.ofNullable(this.pattern);
    }
    /**
     * @return (Updatable) Type of the url lists based on the policy
     * 
     */
    public String type() {
        return this.type;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(NetworkFirewallPolicyUrlListUrlListValue defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String pattern;
        private String type;
        public Builder() {}
        public Builder(NetworkFirewallPolicyUrlListUrlListValue defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.pattern = defaults.pattern;
    	      this.type = defaults.type;
        }

        @CustomType.Setter
        public Builder pattern(@Nullable String pattern) {
            this.pattern = pattern;
            return this;
        }
        @CustomType.Setter
        public Builder type(String type) {
            this.type = Objects.requireNonNull(type);
            return this;
        }
        public NetworkFirewallPolicyUrlListUrlListValue build() {
            final var o = new NetworkFirewallPolicyUrlListUrlListValue();
            o.pattern = pattern;
            o.type = type;
            return o;
        }
    }
}