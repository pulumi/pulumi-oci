// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.NetworkFirewall.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class NetworkFirewallPolicyTunnelInspectionRulePositionArgs extends com.pulumi.resources.ResourceArgs {

    public static final NetworkFirewallPolicyTunnelInspectionRulePositionArgs Empty = new NetworkFirewallPolicyTunnelInspectionRulePositionArgs();

    /**
     * (Updatable) Identifier for rule after which this rule lies.
     * 
     */
    @Import(name="afterRule")
    private @Nullable Output<String> afterRule;

    /**
     * @return (Updatable) Identifier for rule after which this rule lies.
     * 
     */
    public Optional<Output<String>> afterRule() {
        return Optional.ofNullable(this.afterRule);
    }

    /**
     * (Updatable) Identifier for rule before which this rule lies.
     * 
     */
    @Import(name="beforeRule")
    private @Nullable Output<String> beforeRule;

    /**
     * @return (Updatable) Identifier for rule before which this rule lies.
     * 
     */
    public Optional<Output<String>> beforeRule() {
        return Optional.ofNullable(this.beforeRule);
    }

    private NetworkFirewallPolicyTunnelInspectionRulePositionArgs() {}

    private NetworkFirewallPolicyTunnelInspectionRulePositionArgs(NetworkFirewallPolicyTunnelInspectionRulePositionArgs $) {
        this.afterRule = $.afterRule;
        this.beforeRule = $.beforeRule;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(NetworkFirewallPolicyTunnelInspectionRulePositionArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private NetworkFirewallPolicyTunnelInspectionRulePositionArgs $;

        public Builder() {
            $ = new NetworkFirewallPolicyTunnelInspectionRulePositionArgs();
        }

        public Builder(NetworkFirewallPolicyTunnelInspectionRulePositionArgs defaults) {
            $ = new NetworkFirewallPolicyTunnelInspectionRulePositionArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param afterRule (Updatable) Identifier for rule after which this rule lies.
         * 
         * @return builder
         * 
         */
        public Builder afterRule(@Nullable Output<String> afterRule) {
            $.afterRule = afterRule;
            return this;
        }

        /**
         * @param afterRule (Updatable) Identifier for rule after which this rule lies.
         * 
         * @return builder
         * 
         */
        public Builder afterRule(String afterRule) {
            return afterRule(Output.of(afterRule));
        }

        /**
         * @param beforeRule (Updatable) Identifier for rule before which this rule lies.
         * 
         * @return builder
         * 
         */
        public Builder beforeRule(@Nullable Output<String> beforeRule) {
            $.beforeRule = beforeRule;
            return this;
        }

        /**
         * @param beforeRule (Updatable) Identifier for rule before which this rule lies.
         * 
         * @return builder
         * 
         */
        public Builder beforeRule(String beforeRule) {
            return beforeRule(Output.of(beforeRule));
        }

        public NetworkFirewallPolicyTunnelInspectionRulePositionArgs build() {
            return $;
        }
    }

}
