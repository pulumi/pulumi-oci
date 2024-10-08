// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ComputeCloud.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class AtCustomerCccInfrastructureInfrastructureNetworkConfigurationManagementNodeArgs extends com.pulumi.resources.ResourceArgs {

    public static final AtCustomerCccInfrastructureInfrastructureNetworkConfigurationManagementNodeArgs Empty = new AtCustomerCccInfrastructureInfrastructureNetworkConfigurationManagementNodeArgs();

    /**
     * Hostname for interface to the management node.
     * 
     */
    @Import(name="hostname")
    private @Nullable Output<String> hostname;

    /**
     * @return Hostname for interface to the management node.
     * 
     */
    public Optional<Output<String>> hostname() {
        return Optional.ofNullable(this.hostname);
    }

    /**
     * Address of the management node.
     * 
     */
    @Import(name="ip")
    private @Nullable Output<String> ip;

    /**
     * @return Address of the management node.
     * 
     */
    public Optional<Output<String>> ip() {
        return Optional.ofNullable(this.ip);
    }

    private AtCustomerCccInfrastructureInfrastructureNetworkConfigurationManagementNodeArgs() {}

    private AtCustomerCccInfrastructureInfrastructureNetworkConfigurationManagementNodeArgs(AtCustomerCccInfrastructureInfrastructureNetworkConfigurationManagementNodeArgs $) {
        this.hostname = $.hostname;
        this.ip = $.ip;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(AtCustomerCccInfrastructureInfrastructureNetworkConfigurationManagementNodeArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private AtCustomerCccInfrastructureInfrastructureNetworkConfigurationManagementNodeArgs $;

        public Builder() {
            $ = new AtCustomerCccInfrastructureInfrastructureNetworkConfigurationManagementNodeArgs();
        }

        public Builder(AtCustomerCccInfrastructureInfrastructureNetworkConfigurationManagementNodeArgs defaults) {
            $ = new AtCustomerCccInfrastructureInfrastructureNetworkConfigurationManagementNodeArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param hostname Hostname for interface to the management node.
         * 
         * @return builder
         * 
         */
        public Builder hostname(@Nullable Output<String> hostname) {
            $.hostname = hostname;
            return this;
        }

        /**
         * @param hostname Hostname for interface to the management node.
         * 
         * @return builder
         * 
         */
        public Builder hostname(String hostname) {
            return hostname(Output.of(hostname));
        }

        /**
         * @param ip Address of the management node.
         * 
         * @return builder
         * 
         */
        public Builder ip(@Nullable Output<String> ip) {
            $.ip = ip;
            return this;
        }

        /**
         * @param ip Address of the management node.
         * 
         * @return builder
         * 
         */
        public Builder ip(String ip) {
            return ip(Output.of(ip));
        }

        public AtCustomerCccInfrastructureInfrastructureNetworkConfigurationManagementNodeArgs build() {
            return $;
        }
    }

}
