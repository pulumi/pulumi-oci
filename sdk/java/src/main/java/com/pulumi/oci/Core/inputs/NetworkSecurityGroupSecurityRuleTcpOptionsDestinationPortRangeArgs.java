// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Integer;
import java.util.Objects;


public final class NetworkSecurityGroupSecurityRuleTcpOptionsDestinationPortRangeArgs extends com.pulumi.resources.ResourceArgs {

    public static final NetworkSecurityGroupSecurityRuleTcpOptionsDestinationPortRangeArgs Empty = new NetworkSecurityGroupSecurityRuleTcpOptionsDestinationPortRangeArgs();

    /**
     * The maximum port number, which must not be less than the minimum port number. To specify a single port number, set both the min and max to the same value.
     * 
     */
    @Import(name="max", required=true)
    private Output<Integer> max;

    /**
     * @return The maximum port number, which must not be less than the minimum port number. To specify a single port number, set both the min and max to the same value.
     * 
     */
    public Output<Integer> max() {
        return this.max;
    }

    /**
     * The minimum port number, which must not be greater than the maximum port number.
     * 
     */
    @Import(name="min", required=true)
    private Output<Integer> min;

    /**
     * @return The minimum port number, which must not be greater than the maximum port number.
     * 
     */
    public Output<Integer> min() {
        return this.min;
    }

    private NetworkSecurityGroupSecurityRuleTcpOptionsDestinationPortRangeArgs() {}

    private NetworkSecurityGroupSecurityRuleTcpOptionsDestinationPortRangeArgs(NetworkSecurityGroupSecurityRuleTcpOptionsDestinationPortRangeArgs $) {
        this.max = $.max;
        this.min = $.min;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(NetworkSecurityGroupSecurityRuleTcpOptionsDestinationPortRangeArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private NetworkSecurityGroupSecurityRuleTcpOptionsDestinationPortRangeArgs $;

        public Builder() {
            $ = new NetworkSecurityGroupSecurityRuleTcpOptionsDestinationPortRangeArgs();
        }

        public Builder(NetworkSecurityGroupSecurityRuleTcpOptionsDestinationPortRangeArgs defaults) {
            $ = new NetworkSecurityGroupSecurityRuleTcpOptionsDestinationPortRangeArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param max The maximum port number, which must not be less than the minimum port number. To specify a single port number, set both the min and max to the same value.
         * 
         * @return builder
         * 
         */
        public Builder max(Output<Integer> max) {
            $.max = max;
            return this;
        }

        /**
         * @param max The maximum port number, which must not be less than the minimum port number. To specify a single port number, set both the min and max to the same value.
         * 
         * @return builder
         * 
         */
        public Builder max(Integer max) {
            return max(Output.of(max));
        }

        /**
         * @param min The minimum port number, which must not be greater than the maximum port number.
         * 
         * @return builder
         * 
         */
        public Builder min(Output<Integer> min) {
            $.min = min;
            return this;
        }

        /**
         * @param min The minimum port number, which must not be greater than the maximum port number.
         * 
         * @return builder
         * 
         */
        public Builder min(Integer min) {
            return min(Output.of(min));
        }

        public NetworkSecurityGroupSecurityRuleTcpOptionsDestinationPortRangeArgs build() {
            if ($.max == null) {
                throw new MissingRequiredPropertyException("NetworkSecurityGroupSecurityRuleTcpOptionsDestinationPortRangeArgs", "max");
            }
            if ($.min == null) {
                throw new MissingRequiredPropertyException("NetworkSecurityGroupSecurityRuleTcpOptionsDestinationPortRangeArgs", "min");
            }
            return $;
        }
    }

}
