// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.NetworkLoadBalancer.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class NetworkLoadBalancerIpAddressReservedIpArgs extends com.pulumi.resources.ResourceArgs {

    public static final NetworkLoadBalancerIpAddressReservedIpArgs Empty = new NetworkLoadBalancerIpAddressReservedIpArgs();

    /**
     * OCID of the reserved public IP address created with the virtual cloud network.
     * 
     */
    @Import(name="id")
    private @Nullable Output<String> id;

    /**
     * @return OCID of the reserved public IP address created with the virtual cloud network.
     * 
     */
    public Optional<Output<String>> id() {
        return Optional.ofNullable(this.id);
    }

    private NetworkLoadBalancerIpAddressReservedIpArgs() {}

    private NetworkLoadBalancerIpAddressReservedIpArgs(NetworkLoadBalancerIpAddressReservedIpArgs $) {
        this.id = $.id;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(NetworkLoadBalancerIpAddressReservedIpArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private NetworkLoadBalancerIpAddressReservedIpArgs $;

        public Builder() {
            $ = new NetworkLoadBalancerIpAddressReservedIpArgs();
        }

        public Builder(NetworkLoadBalancerIpAddressReservedIpArgs defaults) {
            $ = new NetworkLoadBalancerIpAddressReservedIpArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param id OCID of the reserved public IP address created with the virtual cloud network.
         * 
         * @return builder
         * 
         */
        public Builder id(@Nullable Output<String> id) {
            $.id = id;
            return this;
        }

        /**
         * @param id OCID of the reserved public IP address created with the virtual cloud network.
         * 
         * @return builder
         * 
         */
        public Builder id(String id) {
            return id(Output.of(id));
        }

        public NetworkLoadBalancerIpAddressReservedIpArgs build() {
            return $;
        }
    }

}