// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.NetworkFirewall;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class NetworkFirewallPolicyAddressListArgs extends com.pulumi.resources.ResourceArgs {

    public static final NetworkFirewallPolicyAddressListArgs Empty = new NetworkFirewallPolicyAddressListArgs();

    /**
     * (Updatable) List of addresses.
     * 
     */
    @Import(name="addresses", required=true)
    private Output<List<String>> addresses;

    /**
     * @return (Updatable) List of addresses.
     * 
     */
    public Output<List<String>> addresses() {
        return this.addresses;
    }

    /**
     * Unique name to identify the group of addresses to be used in the policy rules.
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return Unique name to identify the group of addresses to be used in the policy rules.
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * Unique Network Firewall Policy identifier
     * 
     */
    @Import(name="networkFirewallPolicyId", required=true)
    private Output<String> networkFirewallPolicyId;

    /**
     * @return Unique Network Firewall Policy identifier
     * 
     */
    public Output<String> networkFirewallPolicyId() {
        return this.networkFirewallPolicyId;
    }

    /**
     * Type of address List. The accepted values are - * FQDN * IP
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="type", required=true)
    private Output<String> type;

    /**
     * @return Type of address List. The accepted values are - * FQDN * IP
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> type() {
        return this.type;
    }

    private NetworkFirewallPolicyAddressListArgs() {}

    private NetworkFirewallPolicyAddressListArgs(NetworkFirewallPolicyAddressListArgs $) {
        this.addresses = $.addresses;
        this.name = $.name;
        this.networkFirewallPolicyId = $.networkFirewallPolicyId;
        this.type = $.type;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(NetworkFirewallPolicyAddressListArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private NetworkFirewallPolicyAddressListArgs $;

        public Builder() {
            $ = new NetworkFirewallPolicyAddressListArgs();
        }

        public Builder(NetworkFirewallPolicyAddressListArgs defaults) {
            $ = new NetworkFirewallPolicyAddressListArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param addresses (Updatable) List of addresses.
         * 
         * @return builder
         * 
         */
        public Builder addresses(Output<List<String>> addresses) {
            $.addresses = addresses;
            return this;
        }

        /**
         * @param addresses (Updatable) List of addresses.
         * 
         * @return builder
         * 
         */
        public Builder addresses(List<String> addresses) {
            return addresses(Output.of(addresses));
        }

        /**
         * @param addresses (Updatable) List of addresses.
         * 
         * @return builder
         * 
         */
        public Builder addresses(String... addresses) {
            return addresses(List.of(addresses));
        }

        /**
         * @param name Unique name to identify the group of addresses to be used in the policy rules.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name Unique name to identify the group of addresses to be used in the policy rules.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param networkFirewallPolicyId Unique Network Firewall Policy identifier
         * 
         * @return builder
         * 
         */
        public Builder networkFirewallPolicyId(Output<String> networkFirewallPolicyId) {
            $.networkFirewallPolicyId = networkFirewallPolicyId;
            return this;
        }

        /**
         * @param networkFirewallPolicyId Unique Network Firewall Policy identifier
         * 
         * @return builder
         * 
         */
        public Builder networkFirewallPolicyId(String networkFirewallPolicyId) {
            return networkFirewallPolicyId(Output.of(networkFirewallPolicyId));
        }

        /**
         * @param type Type of address List. The accepted values are - * FQDN * IP
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder type(Output<String> type) {
            $.type = type;
            return this;
        }

        /**
         * @param type Type of address List. The accepted values are - * FQDN * IP
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder type(String type) {
            return type(Output.of(type));
        }

        public NetworkFirewallPolicyAddressListArgs build() {
            $.addresses = Objects.requireNonNull($.addresses, "expected parameter 'addresses' to be non-null");
            $.networkFirewallPolicyId = Objects.requireNonNull($.networkFirewallPolicyId, "expected parameter 'networkFirewallPolicyId' to be non-null");
            $.type = Objects.requireNonNull($.type, "expected parameter 'type' to be non-null");
            return $;
        }
    }

}