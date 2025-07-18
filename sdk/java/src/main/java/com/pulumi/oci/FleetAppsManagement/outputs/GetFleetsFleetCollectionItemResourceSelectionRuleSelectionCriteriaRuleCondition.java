// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetFleetsFleetCollectionItemResourceSelectionRuleSelectionCriteriaRuleCondition {
    /**
     * @return Attribute Group. Provide a Tag namespace if the rule is based on a tag. Provide resource type if the rule is based on a resource property.
     * 
     */
    private String attrGroup;
    /**
     * @return Attribute Key.Provide Tag key if the rule is based on a tag. Provide resource property name if the rule is based on a resource property.
     * 
     */
    private String attrKey;
    /**
     * @return Attribute Value.Provide Tag value if the rule is based on a tag. Provide resource property value if the rule is based on a resource property.
     * 
     */
    private String attrValue;

    private GetFleetsFleetCollectionItemResourceSelectionRuleSelectionCriteriaRuleCondition() {}
    /**
     * @return Attribute Group. Provide a Tag namespace if the rule is based on a tag. Provide resource type if the rule is based on a resource property.
     * 
     */
    public String attrGroup() {
        return this.attrGroup;
    }
    /**
     * @return Attribute Key.Provide Tag key if the rule is based on a tag. Provide resource property name if the rule is based on a resource property.
     * 
     */
    public String attrKey() {
        return this.attrKey;
    }
    /**
     * @return Attribute Value.Provide Tag value if the rule is based on a tag. Provide resource property value if the rule is based on a resource property.
     * 
     */
    public String attrValue() {
        return this.attrValue;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetFleetsFleetCollectionItemResourceSelectionRuleSelectionCriteriaRuleCondition defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String attrGroup;
        private String attrKey;
        private String attrValue;
        public Builder() {}
        public Builder(GetFleetsFleetCollectionItemResourceSelectionRuleSelectionCriteriaRuleCondition defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.attrGroup = defaults.attrGroup;
    	      this.attrKey = defaults.attrKey;
    	      this.attrValue = defaults.attrValue;
        }

        @CustomType.Setter
        public Builder attrGroup(String attrGroup) {
            if (attrGroup == null) {
              throw new MissingRequiredPropertyException("GetFleetsFleetCollectionItemResourceSelectionRuleSelectionCriteriaRuleCondition", "attrGroup");
            }
            this.attrGroup = attrGroup;
            return this;
        }
        @CustomType.Setter
        public Builder attrKey(String attrKey) {
            if (attrKey == null) {
              throw new MissingRequiredPropertyException("GetFleetsFleetCollectionItemResourceSelectionRuleSelectionCriteriaRuleCondition", "attrKey");
            }
            this.attrKey = attrKey;
            return this;
        }
        @CustomType.Setter
        public Builder attrValue(String attrValue) {
            if (attrValue == null) {
              throw new MissingRequiredPropertyException("GetFleetsFleetCollectionItemResourceSelectionRuleSelectionCriteriaRuleCondition", "attrValue");
            }
            this.attrValue = attrValue;
            return this;
        }
        public GetFleetsFleetCollectionItemResourceSelectionRuleSelectionCriteriaRuleCondition build() {
            final var _resultValue = new GetFleetsFleetCollectionItemResourceSelectionRuleSelectionCriteriaRuleCondition();
            _resultValue.attrGroup = attrGroup;
            _resultValue.attrKey = attrKey;
            _resultValue.attrValue = attrValue;
            return _resultValue;
        }
    }
}
