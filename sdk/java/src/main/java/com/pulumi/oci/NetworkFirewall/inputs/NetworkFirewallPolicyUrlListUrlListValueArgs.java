// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.NetworkFirewall.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class NetworkFirewallPolicyUrlListUrlListValueArgs extends com.pulumi.resources.ResourceArgs {

    public static final NetworkFirewallPolicyUrlListUrlListValueArgs Empty = new NetworkFirewallPolicyUrlListUrlListValueArgs();

    /**
     * (Updatable) URL lists to allow or deny traffic to a group of URLs. You can include a maximum of 25 URLs in each list.
     * 
     */
    @Import(name="pattern")
    private @Nullable Output<String> pattern;

    /**
     * @return (Updatable) URL lists to allow or deny traffic to a group of URLs. You can include a maximum of 25 URLs in each list.
     * 
     */
    public Optional<Output<String>> pattern() {
        return Optional.ofNullable(this.pattern);
    }

    /**
     * (Updatable) Type of the url lists based on the policy
     * 
     */
    @Import(name="type", required=true)
    private Output<String> type;

    /**
     * @return (Updatable) Type of the url lists based on the policy
     * 
     */
    public Output<String> type() {
        return this.type;
    }

    private NetworkFirewallPolicyUrlListUrlListValueArgs() {}

    private NetworkFirewallPolicyUrlListUrlListValueArgs(NetworkFirewallPolicyUrlListUrlListValueArgs $) {
        this.pattern = $.pattern;
        this.type = $.type;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(NetworkFirewallPolicyUrlListUrlListValueArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private NetworkFirewallPolicyUrlListUrlListValueArgs $;

        public Builder() {
            $ = new NetworkFirewallPolicyUrlListUrlListValueArgs();
        }

        public Builder(NetworkFirewallPolicyUrlListUrlListValueArgs defaults) {
            $ = new NetworkFirewallPolicyUrlListUrlListValueArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param pattern (Updatable) URL lists to allow or deny traffic to a group of URLs. You can include a maximum of 25 URLs in each list.
         * 
         * @return builder
         * 
         */
        public Builder pattern(@Nullable Output<String> pattern) {
            $.pattern = pattern;
            return this;
        }

        /**
         * @param pattern (Updatable) URL lists to allow or deny traffic to a group of URLs. You can include a maximum of 25 URLs in each list.
         * 
         * @return builder
         * 
         */
        public Builder pattern(String pattern) {
            return pattern(Output.of(pattern));
        }

        /**
         * @param type (Updatable) Type of the url lists based on the policy
         * 
         * @return builder
         * 
         */
        public Builder type(Output<String> type) {
            $.type = type;
            return this;
        }

        /**
         * @param type (Updatable) Type of the url lists based on the policy
         * 
         * @return builder
         * 
         */
        public Builder type(String type) {
            return type(Output.of(type));
        }

        public NetworkFirewallPolicyUrlListUrlListValueArgs build() {
            $.type = Objects.requireNonNull($.type, "expected parameter 'type' to be non-null");
            return $;
        }
    }

}