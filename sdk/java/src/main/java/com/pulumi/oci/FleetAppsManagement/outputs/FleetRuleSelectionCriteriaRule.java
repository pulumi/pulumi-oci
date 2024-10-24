// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.FleetAppsManagement.outputs.FleetRuleSelectionCriteriaRuleCondition;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class FleetRuleSelectionCriteriaRule {
    /**
     * @return (Updatable) Rule to be be applied on.
     * 
     */
    private @Nullable String basis;
    /**
     * @return (Updatable) Please provide the root compartmentId (TenancyId).
     * 
     */
    private String compartmentId;
    /**
     * @return (Updatable) Rule Conditions
     * 
     */
    private List<FleetRuleSelectionCriteriaRuleCondition> conditions;
    /**
     * @return (Updatable) Resource Compartment Id.Provide the compartmentId the resource belongs to.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    private String resourceCompartmentId;

    private FleetRuleSelectionCriteriaRule() {}
    /**
     * @return (Updatable) Rule to be be applied on.
     * 
     */
    public Optional<String> basis() {
        return Optional.ofNullable(this.basis);
    }
    /**
     * @return (Updatable) Please provide the root compartmentId (TenancyId).
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return (Updatable) Rule Conditions
     * 
     */
    public List<FleetRuleSelectionCriteriaRuleCondition> conditions() {
        return this.conditions;
    }
    /**
     * @return (Updatable) Resource Compartment Id.Provide the compartmentId the resource belongs to.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public String resourceCompartmentId() {
        return this.resourceCompartmentId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(FleetRuleSelectionCriteriaRule defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String basis;
        private String compartmentId;
        private List<FleetRuleSelectionCriteriaRuleCondition> conditions;
        private String resourceCompartmentId;
        public Builder() {}
        public Builder(FleetRuleSelectionCriteriaRule defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.basis = defaults.basis;
    	      this.compartmentId = defaults.compartmentId;
    	      this.conditions = defaults.conditions;
    	      this.resourceCompartmentId = defaults.resourceCompartmentId;
        }

        @CustomType.Setter
        public Builder basis(@Nullable String basis) {

            this.basis = basis;
            return this;
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("FleetRuleSelectionCriteriaRule", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder conditions(List<FleetRuleSelectionCriteriaRuleCondition> conditions) {
            if (conditions == null) {
              throw new MissingRequiredPropertyException("FleetRuleSelectionCriteriaRule", "conditions");
            }
            this.conditions = conditions;
            return this;
        }
        public Builder conditions(FleetRuleSelectionCriteriaRuleCondition... conditions) {
            return conditions(List.of(conditions));
        }
        @CustomType.Setter
        public Builder resourceCompartmentId(String resourceCompartmentId) {
            if (resourceCompartmentId == null) {
              throw new MissingRequiredPropertyException("FleetRuleSelectionCriteriaRule", "resourceCompartmentId");
            }
            this.resourceCompartmentId = resourceCompartmentId;
            return this;
        }
        public FleetRuleSelectionCriteriaRule build() {
            final var _resultValue = new FleetRuleSelectionCriteriaRule();
            _resultValue.basis = basis;
            _resultValue.compartmentId = compartmentId;
            _resultValue.conditions = conditions;
            _resultValue.resourceCompartmentId = resourceCompartmentId;
            return _resultValue;
        }
    }
}
