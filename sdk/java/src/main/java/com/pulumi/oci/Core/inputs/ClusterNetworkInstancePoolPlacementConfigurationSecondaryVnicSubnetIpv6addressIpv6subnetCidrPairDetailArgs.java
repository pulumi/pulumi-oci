// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ClusterNetworkInstancePoolPlacementConfigurationSecondaryVnicSubnetIpv6addressIpv6subnetCidrPairDetailArgs extends com.pulumi.resources.ResourceArgs {

    public static final ClusterNetworkInstancePoolPlacementConfigurationSecondaryVnicSubnetIpv6addressIpv6subnetCidrPairDetailArgs Empty = new ClusterNetworkInstancePoolPlacementConfigurationSecondaryVnicSubnetIpv6addressIpv6subnetCidrPairDetailArgs();

    /**
     * Optional. Used to disambiguate which subnet prefix should be used to create an IPv6 allocation.
     * 
     */
    @Import(name="ipv6subnetCidr")
    private @Nullable Output<String> ipv6subnetCidr;

    /**
     * @return Optional. Used to disambiguate which subnet prefix should be used to create an IPv6 allocation.
     * 
     */
    public Optional<Output<String>> ipv6subnetCidr() {
        return Optional.ofNullable(this.ipv6subnetCidr);
    }

    private ClusterNetworkInstancePoolPlacementConfigurationSecondaryVnicSubnetIpv6addressIpv6subnetCidrPairDetailArgs() {}

    private ClusterNetworkInstancePoolPlacementConfigurationSecondaryVnicSubnetIpv6addressIpv6subnetCidrPairDetailArgs(ClusterNetworkInstancePoolPlacementConfigurationSecondaryVnicSubnetIpv6addressIpv6subnetCidrPairDetailArgs $) {
        this.ipv6subnetCidr = $.ipv6subnetCidr;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ClusterNetworkInstancePoolPlacementConfigurationSecondaryVnicSubnetIpv6addressIpv6subnetCidrPairDetailArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ClusterNetworkInstancePoolPlacementConfigurationSecondaryVnicSubnetIpv6addressIpv6subnetCidrPairDetailArgs $;

        public Builder() {
            $ = new ClusterNetworkInstancePoolPlacementConfigurationSecondaryVnicSubnetIpv6addressIpv6subnetCidrPairDetailArgs();
        }

        public Builder(ClusterNetworkInstancePoolPlacementConfigurationSecondaryVnicSubnetIpv6addressIpv6subnetCidrPairDetailArgs defaults) {
            $ = new ClusterNetworkInstancePoolPlacementConfigurationSecondaryVnicSubnetIpv6addressIpv6subnetCidrPairDetailArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param ipv6subnetCidr Optional. Used to disambiguate which subnet prefix should be used to create an IPv6 allocation.
         * 
         * @return builder
         * 
         */
        public Builder ipv6subnetCidr(@Nullable Output<String> ipv6subnetCidr) {
            $.ipv6subnetCidr = ipv6subnetCidr;
            return this;
        }

        /**
         * @param ipv6subnetCidr Optional. Used to disambiguate which subnet prefix should be used to create an IPv6 allocation.
         * 
         * @return builder
         * 
         */
        public Builder ipv6subnetCidr(String ipv6subnetCidr) {
            return ipv6subnetCidr(Output.of(ipv6subnetCidr));
        }

        public ClusterNetworkInstancePoolPlacementConfigurationSecondaryVnicSubnetIpv6addressIpv6subnetCidrPairDetailArgs build() {
            return $;
        }
    }

}