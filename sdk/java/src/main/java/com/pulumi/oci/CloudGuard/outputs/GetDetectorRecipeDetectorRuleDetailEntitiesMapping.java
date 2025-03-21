// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudGuard.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDetectorRecipeDetectorRuleDetailEntitiesMapping {
    /**
     * @return Display name of the entity
     * 
     */
    private String displayName;
    /**
     * @return Type of entity
     * 
     */
    private String entityType;
    /**
     * @return The entity value mapped to a data source query
     * 
     */
    private String queryField;

    private GetDetectorRecipeDetectorRuleDetailEntitiesMapping() {}
    /**
     * @return Display name of the entity
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return Type of entity
     * 
     */
    public String entityType() {
        return this.entityType;
    }
    /**
     * @return The entity value mapped to a data source query
     * 
     */
    public String queryField() {
        return this.queryField;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDetectorRecipeDetectorRuleDetailEntitiesMapping defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String displayName;
        private String entityType;
        private String queryField;
        public Builder() {}
        public Builder(GetDetectorRecipeDetectorRuleDetailEntitiesMapping defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.displayName = defaults.displayName;
    	      this.entityType = defaults.entityType;
    	      this.queryField = defaults.queryField;
        }

        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetDetectorRecipeDetectorRuleDetailEntitiesMapping", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder entityType(String entityType) {
            if (entityType == null) {
              throw new MissingRequiredPropertyException("GetDetectorRecipeDetectorRuleDetailEntitiesMapping", "entityType");
            }
            this.entityType = entityType;
            return this;
        }
        @CustomType.Setter
        public Builder queryField(String queryField) {
            if (queryField == null) {
              throw new MissingRequiredPropertyException("GetDetectorRecipeDetectorRuleDetailEntitiesMapping", "queryField");
            }
            this.queryField = queryField;
            return this;
        }
        public GetDetectorRecipeDetectorRuleDetailEntitiesMapping build() {
            final var _resultValue = new GetDetectorRecipeDetectorRuleDetailEntitiesMapping();
            _resultValue.displayName = displayName;
            _resultValue.entityType = entityType;
            _resultValue.queryField = queryField;
            return _resultValue;
        }
    }
}
