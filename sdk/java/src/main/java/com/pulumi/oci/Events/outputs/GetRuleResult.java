// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Events.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Events.outputs.GetRuleAction;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetRuleResult {
    /**
     * @return A list of one or more Action objects.
     * 
     */
    private List<GetRuleAction> actions;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to which this rule belongs.
     * 
     */
    private String compartmentId;
    /**
     * @return A filter that specifies the event that will trigger actions associated with this rule. A few  important things to remember about filters:
     * * Fields not mentioned in the condition are ignored. You can create a valid filter that matches all events with two curly brackets: `{}`
     * 
     */
    private String condition;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    private Map<String,String> definedTags;
    /**
     * @return A string that describes the details of the rule. It does not have to be unique, and you can change it. Avoid entering confidential information.
     * 
     */
    private String description;
    /**
     * @return A string that describes the rule. It does not have to be unique, and you can change it. Avoid entering confidential information.  Example: `&#34;This rule sends a notification upon completion of DbaaS backup.&#34;`
     * 
     */
    private String displayName;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. Exists for cross-compatibility only. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private Map<String,String> freeformTags;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this rule.
     * 
     */
    private String id;
    /**
     * @return Whether or not this rule is currently enabled.  Example: `true`
     * 
     */
    private Boolean isEnabled;
    /**
     * @return A message generated by the Events service about the current state of this rule.
     * 
     */
    private String lifecycleMessage;
    private String ruleId;
    /**
     * @return The current state of the rule.
     * 
     */
    private String state;
    /**
     * @return The time this rule was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2018-09-12T22:47:12.613Z`
     * 
     */
    private String timeCreated;

    private GetRuleResult() {}
    /**
     * @return A list of one or more Action objects.
     * 
     */
    public List<GetRuleAction> actions() {
        return this.actions;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to which this rule belongs.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return A filter that specifies the event that will trigger actions associated with this rule. A few  important things to remember about filters:
     * * Fields not mentioned in the condition are ignored. You can create a valid filter that matches all events with two curly brackets: `{}`
     * 
     */
    public String condition() {
        return this.condition;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Map<String,String> definedTags() {
        return this.definedTags;
    }
    /**
     * @return A string that describes the details of the rule. It does not have to be unique, and you can change it. Avoid entering confidential information.
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return A string that describes the rule. It does not have to be unique, and you can change it. Avoid entering confidential information.  Example: `&#34;This rule sends a notification upon completion of DbaaS backup.&#34;`
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. Exists for cross-compatibility only. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Map<String,String> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this rule.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Whether or not this rule is currently enabled.  Example: `true`
     * 
     */
    public Boolean isEnabled() {
        return this.isEnabled;
    }
    /**
     * @return A message generated by the Events service about the current state of this rule.
     * 
     */
    public String lifecycleMessage() {
        return this.lifecycleMessage;
    }
    public String ruleId() {
        return this.ruleId;
    }
    /**
     * @return The current state of the rule.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return The time this rule was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2018-09-12T22:47:12.613Z`
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetRuleResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetRuleAction> actions;
        private String compartmentId;
        private String condition;
        private Map<String,String> definedTags;
        private String description;
        private String displayName;
        private Map<String,String> freeformTags;
        private String id;
        private Boolean isEnabled;
        private String lifecycleMessage;
        private String ruleId;
        private String state;
        private String timeCreated;
        public Builder() {}
        public Builder(GetRuleResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.actions = defaults.actions;
    	      this.compartmentId = defaults.compartmentId;
    	      this.condition = defaults.condition;
    	      this.definedTags = defaults.definedTags;
    	      this.description = defaults.description;
    	      this.displayName = defaults.displayName;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.isEnabled = defaults.isEnabled;
    	      this.lifecycleMessage = defaults.lifecycleMessage;
    	      this.ruleId = defaults.ruleId;
    	      this.state = defaults.state;
    	      this.timeCreated = defaults.timeCreated;
        }

        @CustomType.Setter
        public Builder actions(List<GetRuleAction> actions) {
            if (actions == null) {
              throw new MissingRequiredPropertyException("GetRuleResult", "actions");
            }
            this.actions = actions;
            return this;
        }
        public Builder actions(GetRuleAction... actions) {
            return actions(List.of(actions));
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetRuleResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder condition(String condition) {
            if (condition == null) {
              throw new MissingRequiredPropertyException("GetRuleResult", "condition");
            }
            this.condition = condition;
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,String> definedTags) {
            if (definedTags == null) {
              throw new MissingRequiredPropertyException("GetRuleResult", "definedTags");
            }
            this.definedTags = definedTags;
            return this;
        }
        @CustomType.Setter
        public Builder description(String description) {
            if (description == null) {
              throw new MissingRequiredPropertyException("GetRuleResult", "description");
            }
            this.description = description;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetRuleResult", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,String> freeformTags) {
            if (freeformTags == null) {
              throw new MissingRequiredPropertyException("GetRuleResult", "freeformTags");
            }
            this.freeformTags = freeformTags;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetRuleResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder isEnabled(Boolean isEnabled) {
            if (isEnabled == null) {
              throw new MissingRequiredPropertyException("GetRuleResult", "isEnabled");
            }
            this.isEnabled = isEnabled;
            return this;
        }
        @CustomType.Setter
        public Builder lifecycleMessage(String lifecycleMessage) {
            if (lifecycleMessage == null) {
              throw new MissingRequiredPropertyException("GetRuleResult", "lifecycleMessage");
            }
            this.lifecycleMessage = lifecycleMessage;
            return this;
        }
        @CustomType.Setter
        public Builder ruleId(String ruleId) {
            if (ruleId == null) {
              throw new MissingRequiredPropertyException("GetRuleResult", "ruleId");
            }
            this.ruleId = ruleId;
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetRuleResult", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetRuleResult", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        public GetRuleResult build() {
            final var _resultValue = new GetRuleResult();
            _resultValue.actions = actions;
            _resultValue.compartmentId = compartmentId;
            _resultValue.condition = condition;
            _resultValue.definedTags = definedTags;
            _resultValue.description = description;
            _resultValue.displayName = displayName;
            _resultValue.freeformTags = freeformTags;
            _resultValue.id = id;
            _resultValue.isEnabled = isEnabled;
            _resultValue.lifecycleMessage = lifecycleMessage;
            _resultValue.ruleId = ruleId;
            _resultValue.state = state;
            _resultValue.timeCreated = timeCreated;
            return _resultValue;
        }
    }
}
