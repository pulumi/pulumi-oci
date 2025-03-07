// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudGuard.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.CloudGuard.outputs.TargetTargetDetailTargetSecurityZoneRecipe;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class TargetTargetDetail {
    /**
     * @return The name of the security zone to associate with this compartment.
     * 
     */
    private @Nullable String securityZoneDisplayName;
    /**
     * @return The OCID of the security zone to associate with this compartment
     * 
     */
    private @Nullable String securityZoneId;
    /**
     * @return Type of resource that target support (COMPARTMENT/FACLOUD)
     * 
     */
    private @Nullable String targetResourceType;
    /**
     * @return The list of security zone recipes to associate with this compartment
     * 
     */
    private @Nullable List<TargetTargetDetailTargetSecurityZoneRecipe> targetSecurityZoneRecipes;

    private TargetTargetDetail() {}
    /**
     * @return The name of the security zone to associate with this compartment.
     * 
     */
    public Optional<String> securityZoneDisplayName() {
        return Optional.ofNullable(this.securityZoneDisplayName);
    }
    /**
     * @return The OCID of the security zone to associate with this compartment
     * 
     */
    public Optional<String> securityZoneId() {
        return Optional.ofNullable(this.securityZoneId);
    }
    /**
     * @return Type of resource that target support (COMPARTMENT/FACLOUD)
     * 
     */
    public Optional<String> targetResourceType() {
        return Optional.ofNullable(this.targetResourceType);
    }
    /**
     * @return The list of security zone recipes to associate with this compartment
     * 
     */
    public List<TargetTargetDetailTargetSecurityZoneRecipe> targetSecurityZoneRecipes() {
        return this.targetSecurityZoneRecipes == null ? List.of() : this.targetSecurityZoneRecipes;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(TargetTargetDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String securityZoneDisplayName;
        private @Nullable String securityZoneId;
        private @Nullable String targetResourceType;
        private @Nullable List<TargetTargetDetailTargetSecurityZoneRecipe> targetSecurityZoneRecipes;
        public Builder() {}
        public Builder(TargetTargetDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.securityZoneDisplayName = defaults.securityZoneDisplayName;
    	      this.securityZoneId = defaults.securityZoneId;
    	      this.targetResourceType = defaults.targetResourceType;
    	      this.targetSecurityZoneRecipes = defaults.targetSecurityZoneRecipes;
        }

        @CustomType.Setter
        public Builder securityZoneDisplayName(@Nullable String securityZoneDisplayName) {

            this.securityZoneDisplayName = securityZoneDisplayName;
            return this;
        }
        @CustomType.Setter
        public Builder securityZoneId(@Nullable String securityZoneId) {

            this.securityZoneId = securityZoneId;
            return this;
        }
        @CustomType.Setter
        public Builder targetResourceType(@Nullable String targetResourceType) {

            this.targetResourceType = targetResourceType;
            return this;
        }
        @CustomType.Setter
        public Builder targetSecurityZoneRecipes(@Nullable List<TargetTargetDetailTargetSecurityZoneRecipe> targetSecurityZoneRecipes) {

            this.targetSecurityZoneRecipes = targetSecurityZoneRecipes;
            return this;
        }
        public Builder targetSecurityZoneRecipes(TargetTargetDetailTargetSecurityZoneRecipe... targetSecurityZoneRecipes) {
            return targetSecurityZoneRecipes(List.of(targetSecurityZoneRecipes));
        }
        public TargetTargetDetail build() {
            final var _resultValue = new TargetTargetDetail();
            _resultValue.securityZoneDisplayName = securityZoneDisplayName;
            _resultValue.securityZoneId = securityZoneId;
            _resultValue.targetResourceType = targetResourceType;
            _resultValue.targetSecurityZoneRecipes = targetSecurityZoneRecipes;
            return _resultValue;
        }
    }
}
