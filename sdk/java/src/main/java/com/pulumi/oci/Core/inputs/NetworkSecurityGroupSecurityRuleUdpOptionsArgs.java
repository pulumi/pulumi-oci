// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Core.inputs.NetworkSecurityGroupSecurityRuleUdpOptionsDestinationPortRangeArgs;
import com.pulumi.oci.Core.inputs.NetworkSecurityGroupSecurityRuleUdpOptionsSourcePortRangeArgs;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class NetworkSecurityGroupSecurityRuleUdpOptionsArgs extends com.pulumi.resources.ResourceArgs {

    public static final NetworkSecurityGroupSecurityRuleUdpOptionsArgs Empty = new NetworkSecurityGroupSecurityRuleUdpOptionsArgs();

    @Import(name="destinationPortRange")
    private @Nullable Output<NetworkSecurityGroupSecurityRuleUdpOptionsDestinationPortRangeArgs> destinationPortRange;

    public Optional<Output<NetworkSecurityGroupSecurityRuleUdpOptionsDestinationPortRangeArgs>> destinationPortRange() {
        return Optional.ofNullable(this.destinationPortRange);
    }

    @Import(name="sourcePortRange")
    private @Nullable Output<NetworkSecurityGroupSecurityRuleUdpOptionsSourcePortRangeArgs> sourcePortRange;

    public Optional<Output<NetworkSecurityGroupSecurityRuleUdpOptionsSourcePortRangeArgs>> sourcePortRange() {
        return Optional.ofNullable(this.sourcePortRange);
    }

    private NetworkSecurityGroupSecurityRuleUdpOptionsArgs() {}

    private NetworkSecurityGroupSecurityRuleUdpOptionsArgs(NetworkSecurityGroupSecurityRuleUdpOptionsArgs $) {
        this.destinationPortRange = $.destinationPortRange;
        this.sourcePortRange = $.sourcePortRange;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(NetworkSecurityGroupSecurityRuleUdpOptionsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private NetworkSecurityGroupSecurityRuleUdpOptionsArgs $;

        public Builder() {
            $ = new NetworkSecurityGroupSecurityRuleUdpOptionsArgs();
        }

        public Builder(NetworkSecurityGroupSecurityRuleUdpOptionsArgs defaults) {
            $ = new NetworkSecurityGroupSecurityRuleUdpOptionsArgs(Objects.requireNonNull(defaults));
        }

        public Builder destinationPortRange(@Nullable Output<NetworkSecurityGroupSecurityRuleUdpOptionsDestinationPortRangeArgs> destinationPortRange) {
            $.destinationPortRange = destinationPortRange;
            return this;
        }

        public Builder destinationPortRange(NetworkSecurityGroupSecurityRuleUdpOptionsDestinationPortRangeArgs destinationPortRange) {
            return destinationPortRange(Output.of(destinationPortRange));
        }

        public Builder sourcePortRange(@Nullable Output<NetworkSecurityGroupSecurityRuleUdpOptionsSourcePortRangeArgs> sourcePortRange) {
            $.sourcePortRange = sourcePortRange;
            return this;
        }

        public Builder sourcePortRange(NetworkSecurityGroupSecurityRuleUdpOptionsSourcePortRangeArgs sourcePortRange) {
            return sourcePortRange(Output.of(sourcePortRange));
        }

        public NetworkSecurityGroupSecurityRuleUdpOptionsArgs build() {
            return $;
        }
    }

}
