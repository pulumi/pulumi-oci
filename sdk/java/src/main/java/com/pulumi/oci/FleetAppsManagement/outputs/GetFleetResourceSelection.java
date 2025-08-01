// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.FleetAppsManagement.outputs.GetFleetResourceSelectionRuleSelectionCriteria;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetFleetResourceSelection {
    /**
     * @return Type of resource selection in a Fleet. Select resources manually or select resources based on rules.
     * 
     */
    private String resourceSelectionType;
    /**
     * @return Rule Selection Criteria for DYNAMIC resource selection for a GENERIC fleet. Rules define what resources are members of this fleet. All resources that meet the criteria are added automatically.
     * 
     */
    private List<GetFleetResourceSelectionRuleSelectionCriteria> ruleSelectionCriterias;

    private GetFleetResourceSelection() {}
    /**
     * @return Type of resource selection in a Fleet. Select resources manually or select resources based on rules.
     * 
     */
    public String resourceSelectionType() {
        return this.resourceSelectionType;
    }
    /**
     * @return Rule Selection Criteria for DYNAMIC resource selection for a GENERIC fleet. Rules define what resources are members of this fleet. All resources that meet the criteria are added automatically.
     * 
     */
    public List<GetFleetResourceSelectionRuleSelectionCriteria> ruleSelectionCriterias() {
        return this.ruleSelectionCriterias;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetFleetResourceSelection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String resourceSelectionType;
        private List<GetFleetResourceSelectionRuleSelectionCriteria> ruleSelectionCriterias;
        public Builder() {}
        public Builder(GetFleetResourceSelection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.resourceSelectionType = defaults.resourceSelectionType;
    	      this.ruleSelectionCriterias = defaults.ruleSelectionCriterias;
        }

        @CustomType.Setter
        public Builder resourceSelectionType(String resourceSelectionType) {
            if (resourceSelectionType == null) {
              throw new MissingRequiredPropertyException("GetFleetResourceSelection", "resourceSelectionType");
            }
            this.resourceSelectionType = resourceSelectionType;
            return this;
        }
        @CustomType.Setter
        public Builder ruleSelectionCriterias(List<GetFleetResourceSelectionRuleSelectionCriteria> ruleSelectionCriterias) {
            if (ruleSelectionCriterias == null) {
              throw new MissingRequiredPropertyException("GetFleetResourceSelection", "ruleSelectionCriterias");
            }
            this.ruleSelectionCriterias = ruleSelectionCriterias;
            return this;
        }
        public Builder ruleSelectionCriterias(GetFleetResourceSelectionRuleSelectionCriteria... ruleSelectionCriterias) {
            return ruleSelectionCriterias(List.of(ruleSelectionCriterias));
        }
        public GetFleetResourceSelection build() {
            final var _resultValue = new GetFleetResourceSelection();
            _resultValue.resourceSelectionType = resourceSelectionType;
            _resultValue.ruleSelectionCriterias = ruleSelectionCriterias;
            return _resultValue;
        }
    }
}
