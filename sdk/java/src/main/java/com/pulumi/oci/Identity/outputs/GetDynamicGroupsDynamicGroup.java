// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetDynamicGroupsDynamicGroup {
    /**
     * @return The OCID of the compartment (remember that the tenancy is simply the root compartment).
     * 
     */
    private String compartmentId;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    private Map<String,String> definedTags;
    /**
     * @return The description you assign to the group. Does not have to be unique, and it&#39;s changeable.
     * 
     */
    private String description;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private Map<String,String> freeformTags;
    /**
     * @return The OCID of the group.
     * 
     */
    private String id;
    /**
     * @return The detailed status of INACTIVE lifecycleState.
     * 
     */
    private String inactiveState;
    /**
     * @return A rule string that defines which instance certificates will be matched. For syntax, see [Managing Dynamic Groups](https://docs.cloud.oracle.com/iaas/Content/Identity/Tasks/managingdynamicgroups.htm).
     * 
     */
    private String matchingRule;
    /**
     * @return A filter to only return resources that match the given name exactly.
     * 
     */
    private String name;
    /**
     * @return A filter to only return resources that match the given lifecycle state.  The state value is case-insensitive.
     * 
     */
    private String state;
    /**
     * @return Date and time the group was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    private String timeCreated;

    private GetDynamicGroupsDynamicGroup() {}
    /**
     * @return The OCID of the compartment (remember that the tenancy is simply the root compartment).
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Map<String,String> definedTags() {
        return this.definedTags;
    }
    /**
     * @return The description you assign to the group. Does not have to be unique, and it&#39;s changeable.
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Map<String,String> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The OCID of the group.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The detailed status of INACTIVE lifecycleState.
     * 
     */
    public String inactiveState() {
        return this.inactiveState;
    }
    /**
     * @return A rule string that defines which instance certificates will be matched. For syntax, see [Managing Dynamic Groups](https://docs.cloud.oracle.com/iaas/Content/Identity/Tasks/managingdynamicgroups.htm).
     * 
     */
    public String matchingRule() {
        return this.matchingRule;
    }
    /**
     * @return A filter to only return resources that match the given name exactly.
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return A filter to only return resources that match the given lifecycle state.  The state value is case-insensitive.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return Date and time the group was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDynamicGroupsDynamicGroup defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private Map<String,String> definedTags;
        private String description;
        private Map<String,String> freeformTags;
        private String id;
        private String inactiveState;
        private String matchingRule;
        private String name;
        private String state;
        private String timeCreated;
        public Builder() {}
        public Builder(GetDynamicGroupsDynamicGroup defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.definedTags = defaults.definedTags;
    	      this.description = defaults.description;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.inactiveState = defaults.inactiveState;
    	      this.matchingRule = defaults.matchingRule;
    	      this.name = defaults.name;
    	      this.state = defaults.state;
    	      this.timeCreated = defaults.timeCreated;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetDynamicGroupsDynamicGroup", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,String> definedTags) {
            if (definedTags == null) {
              throw new MissingRequiredPropertyException("GetDynamicGroupsDynamicGroup", "definedTags");
            }
            this.definedTags = definedTags;
            return this;
        }
        @CustomType.Setter
        public Builder description(String description) {
            if (description == null) {
              throw new MissingRequiredPropertyException("GetDynamicGroupsDynamicGroup", "description");
            }
            this.description = description;
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,String> freeformTags) {
            if (freeformTags == null) {
              throw new MissingRequiredPropertyException("GetDynamicGroupsDynamicGroup", "freeformTags");
            }
            this.freeformTags = freeformTags;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetDynamicGroupsDynamicGroup", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder inactiveState(String inactiveState) {
            if (inactiveState == null) {
              throw new MissingRequiredPropertyException("GetDynamicGroupsDynamicGroup", "inactiveState");
            }
            this.inactiveState = inactiveState;
            return this;
        }
        @CustomType.Setter
        public Builder matchingRule(String matchingRule) {
            if (matchingRule == null) {
              throw new MissingRequiredPropertyException("GetDynamicGroupsDynamicGroup", "matchingRule");
            }
            this.matchingRule = matchingRule;
            return this;
        }
        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("GetDynamicGroupsDynamicGroup", "name");
            }
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetDynamicGroupsDynamicGroup", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetDynamicGroupsDynamicGroup", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        public GetDynamicGroupsDynamicGroup build() {
            final var _resultValue = new GetDynamicGroupsDynamicGroup();
            _resultValue.compartmentId = compartmentId;
            _resultValue.definedTags = definedTags;
            _resultValue.description = description;
            _resultValue.freeformTags = freeformTags;
            _resultValue.id = id;
            _resultValue.inactiveState = inactiveState;
            _resultValue.matchingRule = matchingRule;
            _resultValue.name = name;
            _resultValue.state = state;
            _resultValue.timeCreated = timeCreated;
            return _resultValue;
        }
    }
}
