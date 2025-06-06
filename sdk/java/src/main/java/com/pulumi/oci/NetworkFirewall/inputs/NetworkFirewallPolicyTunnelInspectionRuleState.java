// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.NetworkFirewall.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.NetworkFirewall.inputs.NetworkFirewallPolicyTunnelInspectionRuleConditionArgs;
import com.pulumi.oci.NetworkFirewall.inputs.NetworkFirewallPolicyTunnelInspectionRulePositionArgs;
import com.pulumi.oci.NetworkFirewall.inputs.NetworkFirewallPolicyTunnelInspectionRuleProfileArgs;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class NetworkFirewallPolicyTunnelInspectionRuleState extends com.pulumi.resources.ResourceArgs {

    public static final NetworkFirewallPolicyTunnelInspectionRuleState Empty = new NetworkFirewallPolicyTunnelInspectionRuleState();

    /**
     * (Updatable) Types of Inspect Action on the traffic flow.
     * * INSPECT - Inspect the traffic.
     * * INSPECT_AND_CAPTURE_LOG - Inspect and capture logs for the traffic.
     * 
     */
    @Import(name="action")
    private @Nullable Output<String> action;

    /**
     * @return (Updatable) Types of Inspect Action on the traffic flow.
     * * INSPECT - Inspect the traffic.
     * * INSPECT_AND_CAPTURE_LOG - Inspect and capture logs for the traffic.
     * 
     */
    public Optional<Output<String>> action() {
        return Optional.ofNullable(this.action);
    }

    /**
     * (Updatable) Criteria to evaluate against incoming network traffic. A match occurs when at least one item in the array associated with each specified property corresponds with the relevant aspect of the traffic.
     * 
     */
    @Import(name="condition")
    private @Nullable Output<NetworkFirewallPolicyTunnelInspectionRuleConditionArgs> condition;

    /**
     * @return (Updatable) Criteria to evaluate against incoming network traffic. A match occurs when at least one item in the array associated with each specified property corresponds with the relevant aspect of the traffic.
     * 
     */
    public Optional<Output<NetworkFirewallPolicyTunnelInspectionRuleConditionArgs>> condition() {
        return Optional.ofNullable(this.condition);
    }

    /**
     * Name for the Tunnel Inspection Rule, must be unique within the policy.
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return Name for the Tunnel Inspection Rule, must be unique within the policy.
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * Unique Network Firewall Policy identifier
     * 
     */
    @Import(name="networkFirewallPolicyId")
    private @Nullable Output<String> networkFirewallPolicyId;

    /**
     * @return Unique Network Firewall Policy identifier
     * 
     */
    public Optional<Output<String>> networkFirewallPolicyId() {
        return Optional.ofNullable(this.networkFirewallPolicyId);
    }

    /**
     * OCID of the Network Firewall Policy this Tunnel Inspection Rule belongs to.
     * 
     */
    @Import(name="parentResourceId")
    private @Nullable Output<String> parentResourceId;

    /**
     * @return OCID of the Network Firewall Policy this Tunnel Inspection Rule belongs to.
     * 
     */
    public Optional<Output<String>> parentResourceId() {
        return Optional.ofNullable(this.parentResourceId);
    }

    /**
     * (Updatable) An object which defines the position of the rule.
     * 
     */
    @Import(name="position")
    private @Nullable Output<NetworkFirewallPolicyTunnelInspectionRulePositionArgs> position;

    /**
     * @return (Updatable) An object which defines the position of the rule.
     * 
     */
    public Optional<Output<NetworkFirewallPolicyTunnelInspectionRulePositionArgs>> position() {
        return Optional.ofNullable(this.position);
    }

    /**
     * The priority order in which this rule should be evaluated
     * 
     */
    @Import(name="priorityOrder")
    private @Nullable Output<String> priorityOrder;

    /**
     * @return The priority order in which this rule should be evaluated
     * 
     */
    public Optional<Output<String>> priorityOrder() {
        return Optional.ofNullable(this.priorityOrder);
    }

    /**
     * (Updatable) Vxlan Inspect profile used in Vxlan Tunnel Inspection Rules.
     * 
     */
    @Import(name="profile")
    private @Nullable Output<NetworkFirewallPolicyTunnelInspectionRuleProfileArgs> profile;

    /**
     * @return (Updatable) Vxlan Inspect profile used in Vxlan Tunnel Inspection Rules.
     * 
     */
    public Optional<Output<NetworkFirewallPolicyTunnelInspectionRuleProfileArgs>> profile() {
        return Optional.ofNullable(this.profile);
    }

    /**
     * (Updatable) Types of Tunnel Inspection Protocol to be applied on the traffic.
     * * VXLAN - VXLAN Tunnel Inspection Protocol will be applied on the traffic.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="protocol")
    private @Nullable Output<String> protocol;

    /**
     * @return (Updatable) Types of Tunnel Inspection Protocol to be applied on the traffic.
     * * VXLAN - VXLAN Tunnel Inspection Protocol will be applied on the traffic.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<Output<String>> protocol() {
        return Optional.ofNullable(this.protocol);
    }

    private NetworkFirewallPolicyTunnelInspectionRuleState() {}

    private NetworkFirewallPolicyTunnelInspectionRuleState(NetworkFirewallPolicyTunnelInspectionRuleState $) {
        this.action = $.action;
        this.condition = $.condition;
        this.name = $.name;
        this.networkFirewallPolicyId = $.networkFirewallPolicyId;
        this.parentResourceId = $.parentResourceId;
        this.position = $.position;
        this.priorityOrder = $.priorityOrder;
        this.profile = $.profile;
        this.protocol = $.protocol;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(NetworkFirewallPolicyTunnelInspectionRuleState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private NetworkFirewallPolicyTunnelInspectionRuleState $;

        public Builder() {
            $ = new NetworkFirewallPolicyTunnelInspectionRuleState();
        }

        public Builder(NetworkFirewallPolicyTunnelInspectionRuleState defaults) {
            $ = new NetworkFirewallPolicyTunnelInspectionRuleState(Objects.requireNonNull(defaults));
        }

        /**
         * @param action (Updatable) Types of Inspect Action on the traffic flow.
         * * INSPECT - Inspect the traffic.
         * * INSPECT_AND_CAPTURE_LOG - Inspect and capture logs for the traffic.
         * 
         * @return builder
         * 
         */
        public Builder action(@Nullable Output<String> action) {
            $.action = action;
            return this;
        }

        /**
         * @param action (Updatable) Types of Inspect Action on the traffic flow.
         * * INSPECT - Inspect the traffic.
         * * INSPECT_AND_CAPTURE_LOG - Inspect and capture logs for the traffic.
         * 
         * @return builder
         * 
         */
        public Builder action(String action) {
            return action(Output.of(action));
        }

        /**
         * @param condition (Updatable) Criteria to evaluate against incoming network traffic. A match occurs when at least one item in the array associated with each specified property corresponds with the relevant aspect of the traffic.
         * 
         * @return builder
         * 
         */
        public Builder condition(@Nullable Output<NetworkFirewallPolicyTunnelInspectionRuleConditionArgs> condition) {
            $.condition = condition;
            return this;
        }

        /**
         * @param condition (Updatable) Criteria to evaluate against incoming network traffic. A match occurs when at least one item in the array associated with each specified property corresponds with the relevant aspect of the traffic.
         * 
         * @return builder
         * 
         */
        public Builder condition(NetworkFirewallPolicyTunnelInspectionRuleConditionArgs condition) {
            return condition(Output.of(condition));
        }

        /**
         * @param name Name for the Tunnel Inspection Rule, must be unique within the policy.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name Name for the Tunnel Inspection Rule, must be unique within the policy.
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
        public Builder networkFirewallPolicyId(@Nullable Output<String> networkFirewallPolicyId) {
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
         * @param parentResourceId OCID of the Network Firewall Policy this Tunnel Inspection Rule belongs to.
         * 
         * @return builder
         * 
         */
        public Builder parentResourceId(@Nullable Output<String> parentResourceId) {
            $.parentResourceId = parentResourceId;
            return this;
        }

        /**
         * @param parentResourceId OCID of the Network Firewall Policy this Tunnel Inspection Rule belongs to.
         * 
         * @return builder
         * 
         */
        public Builder parentResourceId(String parentResourceId) {
            return parentResourceId(Output.of(parentResourceId));
        }

        /**
         * @param position (Updatable) An object which defines the position of the rule.
         * 
         * @return builder
         * 
         */
        public Builder position(@Nullable Output<NetworkFirewallPolicyTunnelInspectionRulePositionArgs> position) {
            $.position = position;
            return this;
        }

        /**
         * @param position (Updatable) An object which defines the position of the rule.
         * 
         * @return builder
         * 
         */
        public Builder position(NetworkFirewallPolicyTunnelInspectionRulePositionArgs position) {
            return position(Output.of(position));
        }

        /**
         * @param priorityOrder The priority order in which this rule should be evaluated
         * 
         * @return builder
         * 
         */
        public Builder priorityOrder(@Nullable Output<String> priorityOrder) {
            $.priorityOrder = priorityOrder;
            return this;
        }

        /**
         * @param priorityOrder The priority order in which this rule should be evaluated
         * 
         * @return builder
         * 
         */
        public Builder priorityOrder(String priorityOrder) {
            return priorityOrder(Output.of(priorityOrder));
        }

        /**
         * @param profile (Updatable) Vxlan Inspect profile used in Vxlan Tunnel Inspection Rules.
         * 
         * @return builder
         * 
         */
        public Builder profile(@Nullable Output<NetworkFirewallPolicyTunnelInspectionRuleProfileArgs> profile) {
            $.profile = profile;
            return this;
        }

        /**
         * @param profile (Updatable) Vxlan Inspect profile used in Vxlan Tunnel Inspection Rules.
         * 
         * @return builder
         * 
         */
        public Builder profile(NetworkFirewallPolicyTunnelInspectionRuleProfileArgs profile) {
            return profile(Output.of(profile));
        }

        /**
         * @param protocol (Updatable) Types of Tunnel Inspection Protocol to be applied on the traffic.
         * * VXLAN - VXLAN Tunnel Inspection Protocol will be applied on the traffic.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder protocol(@Nullable Output<String> protocol) {
            $.protocol = protocol;
            return this;
        }

        /**
         * @param protocol (Updatable) Types of Tunnel Inspection Protocol to be applied on the traffic.
         * * VXLAN - VXLAN Tunnel Inspection Protocol will be applied on the traffic.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder protocol(String protocol) {
            return protocol(Output.of(protocol));
        }

        public NetworkFirewallPolicyTunnelInspectionRuleState build() {
            return $;
        }
    }

}
