// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudGuard.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetGuardTargetTargetDetectorRecipeDetectorRuleEntitiesMapping {
    /**
     * @return ResponderRule display name.
     * 
     */
    private String displayName;
    /**
     * @return Possible type of entity
     * 
     */
    private String entityType;
    /**
     * @return The entity value mapped to a data source query
     * 
     */
    private String queryField;

    private GetGuardTargetTargetDetectorRecipeDetectorRuleEntitiesMapping() {}
    /**
     * @return ResponderRule display name.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return Possible type of entity
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

    public static Builder builder(GetGuardTargetTargetDetectorRecipeDetectorRuleEntitiesMapping defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String displayName;
        private String entityType;
        private String queryField;
        public Builder() {}
        public Builder(GetGuardTargetTargetDetectorRecipeDetectorRuleEntitiesMapping defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.displayName = defaults.displayName;
    	      this.entityType = defaults.entityType;
    	      this.queryField = defaults.queryField;
        }

        @CustomType.Setter
        public Builder displayName(String displayName) {
            this.displayName = Objects.requireNonNull(displayName);
            return this;
        }
        @CustomType.Setter
        public Builder entityType(String entityType) {
            this.entityType = Objects.requireNonNull(entityType);
            return this;
        }
        @CustomType.Setter
        public Builder queryField(String queryField) {
            this.queryField = Objects.requireNonNull(queryField);
            return this;
        }
        public GetGuardTargetTargetDetectorRecipeDetectorRuleEntitiesMapping build() {
            final var o = new GetGuardTargetTargetDetectorRecipeDetectorRuleEntitiesMapping();
            o.displayName = displayName;
            o.entityType = entityType;
            o.queryField = queryField;
            return o;
        }
    }
}