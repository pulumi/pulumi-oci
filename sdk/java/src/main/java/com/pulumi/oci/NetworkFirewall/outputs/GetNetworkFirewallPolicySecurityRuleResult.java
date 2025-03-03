// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.NetworkFirewall.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.NetworkFirewall.outputs.GetNetworkFirewallPolicySecurityRuleCondition;
import com.pulumi.oci.NetworkFirewall.outputs.GetNetworkFirewallPolicySecurityRulePosition;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetNetworkFirewallPolicySecurityRuleResult {
    /**
     * @return Types of Action on the Traffic flow.
     * * ALLOW - Allows the traffic.
     * * DROP - Silently drops the traffic, e.g. without sending a TCP reset.
     * * REJECT - Rejects the traffic, sending a TCP reset to client and/or server as applicable.
     * * INSPECT - Inspects traffic for vulnerability as specified in `inspection`, which may result in rejection.
     * 
     */
    private String action;
    /**
     * @return Criteria to evaluate against network traffic. A match occurs when at least one item in the array associated with each specified property corresponds with the relevant aspect of the traffic.
     * 
     */
    private List<GetNetworkFirewallPolicySecurityRuleCondition> conditions;
    private String id;
    /**
     * @return Type of inspection to affect the Traffic flow. This is only applicable if action is INSPECT.
     * * INTRUSION_DETECTION - Intrusion Detection.
     * * INTRUSION_PREVENTION - Intrusion Detection and Prevention. Traffic classified as potentially malicious will be rejected as described in `type`.
     * 
     */
    private String inspection;
    /**
     * @return Name for the Security rule, must be unique within the policy.
     * 
     */
    private String name;
    private String networkFirewallPolicyId;
    /**
     * @return OCID of the Network Firewall Policy this security rule belongs to.
     * 
     */
    private String parentResourceId;
    /**
     * @return An object which defines the position of the rule.
     * 
     */
    private List<GetNetworkFirewallPolicySecurityRulePosition> positions;
    private String priorityOrder;

    private GetNetworkFirewallPolicySecurityRuleResult() {}
    /**
     * @return Types of Action on the Traffic flow.
     * * ALLOW - Allows the traffic.
     * * DROP - Silently drops the traffic, e.g. without sending a TCP reset.
     * * REJECT - Rejects the traffic, sending a TCP reset to client and/or server as applicable.
     * * INSPECT - Inspects traffic for vulnerability as specified in `inspection`, which may result in rejection.
     * 
     */
    public String action() {
        return this.action;
    }
    /**
     * @return Criteria to evaluate against network traffic. A match occurs when at least one item in the array associated with each specified property corresponds with the relevant aspect of the traffic.
     * 
     */
    public List<GetNetworkFirewallPolicySecurityRuleCondition> conditions() {
        return this.conditions;
    }
    public String id() {
        return this.id;
    }
    /**
     * @return Type of inspection to affect the Traffic flow. This is only applicable if action is INSPECT.
     * * INTRUSION_DETECTION - Intrusion Detection.
     * * INTRUSION_PREVENTION - Intrusion Detection and Prevention. Traffic classified as potentially malicious will be rejected as described in `type`.
     * 
     */
    public String inspection() {
        return this.inspection;
    }
    /**
     * @return Name for the Security rule, must be unique within the policy.
     * 
     */
    public String name() {
        return this.name;
    }
    public String networkFirewallPolicyId() {
        return this.networkFirewallPolicyId;
    }
    /**
     * @return OCID of the Network Firewall Policy this security rule belongs to.
     * 
     */
    public String parentResourceId() {
        return this.parentResourceId;
    }
    /**
     * @return An object which defines the position of the rule.
     * 
     */
    public List<GetNetworkFirewallPolicySecurityRulePosition> positions() {
        return this.positions;
    }
    public String priorityOrder() {
        return this.priorityOrder;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetNetworkFirewallPolicySecurityRuleResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String action;
        private List<GetNetworkFirewallPolicySecurityRuleCondition> conditions;
        private String id;
        private String inspection;
        private String name;
        private String networkFirewallPolicyId;
        private String parentResourceId;
        private List<GetNetworkFirewallPolicySecurityRulePosition> positions;
        private String priorityOrder;
        public Builder() {}
        public Builder(GetNetworkFirewallPolicySecurityRuleResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.action = defaults.action;
    	      this.conditions = defaults.conditions;
    	      this.id = defaults.id;
    	      this.inspection = defaults.inspection;
    	      this.name = defaults.name;
    	      this.networkFirewallPolicyId = defaults.networkFirewallPolicyId;
    	      this.parentResourceId = defaults.parentResourceId;
    	      this.positions = defaults.positions;
    	      this.priorityOrder = defaults.priorityOrder;
        }

        @CustomType.Setter
        public Builder action(String action) {
            if (action == null) {
              throw new MissingRequiredPropertyException("GetNetworkFirewallPolicySecurityRuleResult", "action");
            }
            this.action = action;
            return this;
        }
        @CustomType.Setter
        public Builder conditions(List<GetNetworkFirewallPolicySecurityRuleCondition> conditions) {
            if (conditions == null) {
              throw new MissingRequiredPropertyException("GetNetworkFirewallPolicySecurityRuleResult", "conditions");
            }
            this.conditions = conditions;
            return this;
        }
        public Builder conditions(GetNetworkFirewallPolicySecurityRuleCondition... conditions) {
            return conditions(List.of(conditions));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetNetworkFirewallPolicySecurityRuleResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder inspection(String inspection) {
            if (inspection == null) {
              throw new MissingRequiredPropertyException("GetNetworkFirewallPolicySecurityRuleResult", "inspection");
            }
            this.inspection = inspection;
            return this;
        }
        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("GetNetworkFirewallPolicySecurityRuleResult", "name");
            }
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder networkFirewallPolicyId(String networkFirewallPolicyId) {
            if (networkFirewallPolicyId == null) {
              throw new MissingRequiredPropertyException("GetNetworkFirewallPolicySecurityRuleResult", "networkFirewallPolicyId");
            }
            this.networkFirewallPolicyId = networkFirewallPolicyId;
            return this;
        }
        @CustomType.Setter
        public Builder parentResourceId(String parentResourceId) {
            if (parentResourceId == null) {
              throw new MissingRequiredPropertyException("GetNetworkFirewallPolicySecurityRuleResult", "parentResourceId");
            }
            this.parentResourceId = parentResourceId;
            return this;
        }
        @CustomType.Setter
        public Builder positions(List<GetNetworkFirewallPolicySecurityRulePosition> positions) {
            if (positions == null) {
              throw new MissingRequiredPropertyException("GetNetworkFirewallPolicySecurityRuleResult", "positions");
            }
            this.positions = positions;
            return this;
        }
        public Builder positions(GetNetworkFirewallPolicySecurityRulePosition... positions) {
            return positions(List.of(positions));
        }
        @CustomType.Setter
        public Builder priorityOrder(String priorityOrder) {
            if (priorityOrder == null) {
              throw new MissingRequiredPropertyException("GetNetworkFirewallPolicySecurityRuleResult", "priorityOrder");
            }
            this.priorityOrder = priorityOrder;
            return this;
        }
        public GetNetworkFirewallPolicySecurityRuleResult build() {
            final var _resultValue = new GetNetworkFirewallPolicySecurityRuleResult();
            _resultValue.action = action;
            _resultValue.conditions = conditions;
            _resultValue.id = id;
            _resultValue.inspection = inspection;
            _resultValue.name = name;
            _resultValue.networkFirewallPolicyId = networkFirewallPolicyId;
            _resultValue.parentResourceId = parentResourceId;
            _resultValue.positions = positions;
            _resultValue.priorityOrder = priorityOrder;
            return _resultValue;
        }
    }
}
