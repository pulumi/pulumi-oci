// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.NetworkFirewall.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class NetworkFirewallPolicyUrlList {
    private String key;
    private @Nullable String pattern;
    /**
     * @return (Updatable) Type of the secrets mapped based on the policy.
     * * `SSL_INBOUND_INSPECTION`: For Inbound inspection of SSL traffic.
     * * `SSL_FORWARD_PROXY`: For forward proxy certificates for SSL inspection.
     * 
     */
    private String type;

    private NetworkFirewallPolicyUrlList() {}
    public String key() {
        return this.key;
    }
    public Optional<String> pattern() {
        return Optional.ofNullable(this.pattern);
    }
    /**
     * @return (Updatable) Type of the secrets mapped based on the policy.
     * * `SSL_INBOUND_INSPECTION`: For Inbound inspection of SSL traffic.
     * * `SSL_FORWARD_PROXY`: For forward proxy certificates for SSL inspection.
     * 
     */
    public String type() {
        return this.type;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(NetworkFirewallPolicyUrlList defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String key;
        private @Nullable String pattern;
        private String type;
        public Builder() {}
        public Builder(NetworkFirewallPolicyUrlList defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.key = defaults.key;
    	      this.pattern = defaults.pattern;
    	      this.type = defaults.type;
        }

        @CustomType.Setter
        public Builder key(String key) {
            this.key = Objects.requireNonNull(key);
            return this;
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
        public NetworkFirewallPolicyUrlList build() {
            final var o = new NetworkFirewallPolicyUrlList();
            o.key = key;
            o.pattern = pattern;
            o.type = type;
            return o;
        }
    }
}