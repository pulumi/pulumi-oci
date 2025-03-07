// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudGuard.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class TargetTargetDetectorRecipeEffectiveDetectorRuleDetailConditionGroup {
    /**
     * @return Compartment OCID where the resource is created
     * 
     */
    private @Nullable String compartmentId;
    /**
     * @return The base condition resource.
     * 
     */
    private @Nullable String condition;

    private TargetTargetDetectorRecipeEffectiveDetectorRuleDetailConditionGroup() {}
    /**
     * @return Compartment OCID where the resource is created
     * 
     */
    public Optional<String> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }
    /**
     * @return The base condition resource.
     * 
     */
    public Optional<String> condition() {
        return Optional.ofNullable(this.condition);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(TargetTargetDetectorRecipeEffectiveDetectorRuleDetailConditionGroup defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String compartmentId;
        private @Nullable String condition;
        public Builder() {}
        public Builder(TargetTargetDetectorRecipeEffectiveDetectorRuleDetailConditionGroup defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.condition = defaults.condition;
        }

        @CustomType.Setter
        public Builder compartmentId(@Nullable String compartmentId) {

            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder condition(@Nullable String condition) {

            this.condition = condition;
            return this;
        }
        public TargetTargetDetectorRecipeEffectiveDetectorRuleDetailConditionGroup build() {
            final var _resultValue = new TargetTargetDetectorRecipeEffectiveDetectorRuleDetailConditionGroup();
            _resultValue.compartmentId = compartmentId;
            _resultValue.condition = condition;
            return _resultValue;
        }
    }
}
