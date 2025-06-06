// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.BigDataService.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class BdsInstanceNetworkConfigArgs extends com.pulumi.resources.ResourceArgs {

    public static final BdsInstanceNetworkConfigArgs Empty = new BdsInstanceNetworkConfigArgs();

    /**
     * (Updatable) The CIDR IP address block of the VCN.
     * 
     */
    @Import(name="cidrBlock")
    private @Nullable Output<String> cidrBlock;

    /**
     * @return (Updatable) The CIDR IP address block of the VCN.
     * 
     */
    public Optional<Output<String>> cidrBlock() {
        return Optional.ofNullable(this.cidrBlock);
    }

    /**
     * (Updatable) A boolean flag whether to configure a NAT gateway.
     * 
     */
    @Import(name="isNatGatewayRequired")
    private @Nullable Output<Boolean> isNatGatewayRequired;

    /**
     * @return (Updatable) A boolean flag whether to configure a NAT gateway.
     * 
     */
    public Optional<Output<Boolean>> isNatGatewayRequired() {
        return Optional.ofNullable(this.isNatGatewayRequired);
    }

    private BdsInstanceNetworkConfigArgs() {}

    private BdsInstanceNetworkConfigArgs(BdsInstanceNetworkConfigArgs $) {
        this.cidrBlock = $.cidrBlock;
        this.isNatGatewayRequired = $.isNatGatewayRequired;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(BdsInstanceNetworkConfigArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private BdsInstanceNetworkConfigArgs $;

        public Builder() {
            $ = new BdsInstanceNetworkConfigArgs();
        }

        public Builder(BdsInstanceNetworkConfigArgs defaults) {
            $ = new BdsInstanceNetworkConfigArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param cidrBlock (Updatable) The CIDR IP address block of the VCN.
         * 
         * @return builder
         * 
         */
        public Builder cidrBlock(@Nullable Output<String> cidrBlock) {
            $.cidrBlock = cidrBlock;
            return this;
        }

        /**
         * @param cidrBlock (Updatable) The CIDR IP address block of the VCN.
         * 
         * @return builder
         * 
         */
        public Builder cidrBlock(String cidrBlock) {
            return cidrBlock(Output.of(cidrBlock));
        }

        /**
         * @param isNatGatewayRequired (Updatable) A boolean flag whether to configure a NAT gateway.
         * 
         * @return builder
         * 
         */
        public Builder isNatGatewayRequired(@Nullable Output<Boolean> isNatGatewayRequired) {
            $.isNatGatewayRequired = isNatGatewayRequired;
            return this;
        }

        /**
         * @param isNatGatewayRequired (Updatable) A boolean flag whether to configure a NAT gateway.
         * 
         * @return builder
         * 
         */
        public Builder isNatGatewayRequired(Boolean isNatGatewayRequired) {
            return isNatGatewayRequired(Output.of(isNatGatewayRequired));
        }

        public BdsInstanceNetworkConfigArgs build() {
            return $;
        }
    }

}
