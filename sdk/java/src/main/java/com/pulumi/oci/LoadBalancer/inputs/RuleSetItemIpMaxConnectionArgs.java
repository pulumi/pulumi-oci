// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LoadBalancer.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class RuleSetItemIpMaxConnectionArgs extends com.pulumi.resources.ResourceArgs {

    public static final RuleSetItemIpMaxConnectionArgs Empty = new RuleSetItemIpMaxConnectionArgs();

    /**
     * (Updatable) Each element in the list should be valid IPv4 or IPv6 CIDR Block address. Example: &#39;[&#34;129.213.176.0/24&#34;, &#34;150.136.187.0/24&#34;, &#34;2002::1234:abcd:ffff:c0a8:101/64&#34;]&#39;
     * 
     */
    @Import(name="ipAddresses")
    private @Nullable Output<List<String>> ipAddresses;

    /**
     * @return (Updatable) Each element in the list should be valid IPv4 or IPv6 CIDR Block address. Example: &#39;[&#34;129.213.176.0/24&#34;, &#34;150.136.187.0/24&#34;, &#34;2002::1234:abcd:ffff:c0a8:101/64&#34;]&#39;
     * 
     */
    public Optional<Output<List<String>>> ipAddresses() {
        return Optional.ofNullable(this.ipAddresses);
    }

    /**
     * (Updatable) The maximum number of simultaneous connections that the specified IPs can make to the Listener. IPs without a maxConnections setting can make either defaultMaxConnections simultaneous connections to a listener or, if no defaultMaxConnections is specified, an unlimited number of simultaneous connections to a listener.
     * 
     */
    @Import(name="maxConnections")
    private @Nullable Output<Integer> maxConnections;

    /**
     * @return (Updatable) The maximum number of simultaneous connections that the specified IPs can make to the Listener. IPs without a maxConnections setting can make either defaultMaxConnections simultaneous connections to a listener or, if no defaultMaxConnections is specified, an unlimited number of simultaneous connections to a listener.
     * 
     */
    public Optional<Output<Integer>> maxConnections() {
        return Optional.ofNullable(this.maxConnections);
    }

    private RuleSetItemIpMaxConnectionArgs() {}

    private RuleSetItemIpMaxConnectionArgs(RuleSetItemIpMaxConnectionArgs $) {
        this.ipAddresses = $.ipAddresses;
        this.maxConnections = $.maxConnections;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(RuleSetItemIpMaxConnectionArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private RuleSetItemIpMaxConnectionArgs $;

        public Builder() {
            $ = new RuleSetItemIpMaxConnectionArgs();
        }

        public Builder(RuleSetItemIpMaxConnectionArgs defaults) {
            $ = new RuleSetItemIpMaxConnectionArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param ipAddresses (Updatable) Each element in the list should be valid IPv4 or IPv6 CIDR Block address. Example: &#39;[&#34;129.213.176.0/24&#34;, &#34;150.136.187.0/24&#34;, &#34;2002::1234:abcd:ffff:c0a8:101/64&#34;]&#39;
         * 
         * @return builder
         * 
         */
        public Builder ipAddresses(@Nullable Output<List<String>> ipAddresses) {
            $.ipAddresses = ipAddresses;
            return this;
        }

        /**
         * @param ipAddresses (Updatable) Each element in the list should be valid IPv4 or IPv6 CIDR Block address. Example: &#39;[&#34;129.213.176.0/24&#34;, &#34;150.136.187.0/24&#34;, &#34;2002::1234:abcd:ffff:c0a8:101/64&#34;]&#39;
         * 
         * @return builder
         * 
         */
        public Builder ipAddresses(List<String> ipAddresses) {
            return ipAddresses(Output.of(ipAddresses));
        }

        /**
         * @param ipAddresses (Updatable) Each element in the list should be valid IPv4 or IPv6 CIDR Block address. Example: &#39;[&#34;129.213.176.0/24&#34;, &#34;150.136.187.0/24&#34;, &#34;2002::1234:abcd:ffff:c0a8:101/64&#34;]&#39;
         * 
         * @return builder
         * 
         */
        public Builder ipAddresses(String... ipAddresses) {
            return ipAddresses(List.of(ipAddresses));
        }

        /**
         * @param maxConnections (Updatable) The maximum number of simultaneous connections that the specified IPs can make to the Listener. IPs without a maxConnections setting can make either defaultMaxConnections simultaneous connections to a listener or, if no defaultMaxConnections is specified, an unlimited number of simultaneous connections to a listener.
         * 
         * @return builder
         * 
         */
        public Builder maxConnections(@Nullable Output<Integer> maxConnections) {
            $.maxConnections = maxConnections;
            return this;
        }

        /**
         * @param maxConnections (Updatable) The maximum number of simultaneous connections that the specified IPs can make to the Listener. IPs without a maxConnections setting can make either defaultMaxConnections simultaneous connections to a listener or, if no defaultMaxConnections is specified, an unlimited number of simultaneous connections to a listener.
         * 
         * @return builder
         * 
         */
        public Builder maxConnections(Integer maxConnections) {
            return maxConnections(Output.of(maxConnections));
        }

        public RuleSetItemIpMaxConnectionArgs build() {
            return $;
        }
    }

}
