// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudGuard.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.CloudGuard.outputs.GetGuardTargetTargetDetailTargetSecurityZoneRecipe;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetGuardTargetTargetDetail {
    /**
     * @return The name of the security zone to associate with this compartment.
     * 
     */
    private String securityZoneDisplayName;
    /**
     * @return The OCID of the security zone to associate with this compartment
     * 
     */
    private String securityZoneId;
    /**
     * @return Type of target
     * 
     */
    private String targetResourceType;
    /**
     * @return The list of security zone recipes to associate with this compartment
     * 
     */
    private List<GetGuardTargetTargetDetailTargetSecurityZoneRecipe> targetSecurityZoneRecipes;

    private GetGuardTargetTargetDetail() {}
    /**
     * @return The name of the security zone to associate with this compartment.
     * 
     */
    public String securityZoneDisplayName() {
        return this.securityZoneDisplayName;
    }
    /**
     * @return The OCID of the security zone to associate with this compartment
     * 
     */
    public String securityZoneId() {
        return this.securityZoneId;
    }
    /**
     * @return Type of target
     * 
     */
    public String targetResourceType() {
        return this.targetResourceType;
    }
    /**
     * @return The list of security zone recipes to associate with this compartment
     * 
     */
    public List<GetGuardTargetTargetDetailTargetSecurityZoneRecipe> targetSecurityZoneRecipes() {
        return this.targetSecurityZoneRecipes;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetGuardTargetTargetDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String securityZoneDisplayName;
        private String securityZoneId;
        private String targetResourceType;
        private List<GetGuardTargetTargetDetailTargetSecurityZoneRecipe> targetSecurityZoneRecipes;
        public Builder() {}
        public Builder(GetGuardTargetTargetDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.securityZoneDisplayName = defaults.securityZoneDisplayName;
    	      this.securityZoneId = defaults.securityZoneId;
    	      this.targetResourceType = defaults.targetResourceType;
    	      this.targetSecurityZoneRecipes = defaults.targetSecurityZoneRecipes;
        }

        @CustomType.Setter
        public Builder securityZoneDisplayName(String securityZoneDisplayName) {
            if (securityZoneDisplayName == null) {
              throw new MissingRequiredPropertyException("GetGuardTargetTargetDetail", "securityZoneDisplayName");
            }
            this.securityZoneDisplayName = securityZoneDisplayName;
            return this;
        }
        @CustomType.Setter
        public Builder securityZoneId(String securityZoneId) {
            if (securityZoneId == null) {
              throw new MissingRequiredPropertyException("GetGuardTargetTargetDetail", "securityZoneId");
            }
            this.securityZoneId = securityZoneId;
            return this;
        }
        @CustomType.Setter
        public Builder targetResourceType(String targetResourceType) {
            if (targetResourceType == null) {
              throw new MissingRequiredPropertyException("GetGuardTargetTargetDetail", "targetResourceType");
            }
            this.targetResourceType = targetResourceType;
            return this;
        }
        @CustomType.Setter
        public Builder targetSecurityZoneRecipes(List<GetGuardTargetTargetDetailTargetSecurityZoneRecipe> targetSecurityZoneRecipes) {
            if (targetSecurityZoneRecipes == null) {
              throw new MissingRequiredPropertyException("GetGuardTargetTargetDetail", "targetSecurityZoneRecipes");
            }
            this.targetSecurityZoneRecipes = targetSecurityZoneRecipes;
            return this;
        }
        public Builder targetSecurityZoneRecipes(GetGuardTargetTargetDetailTargetSecurityZoneRecipe... targetSecurityZoneRecipes) {
            return targetSecurityZoneRecipes(List.of(targetSecurityZoneRecipes));
        }
        public GetGuardTargetTargetDetail build() {
            final var _resultValue = new GetGuardTargetTargetDetail();
            _resultValue.securityZoneDisplayName = securityZoneDisplayName;
            _resultValue.securityZoneId = securityZoneId;
            _resultValue.targetResourceType = targetResourceType;
            _resultValue.targetSecurityZoneRecipes = targetSecurityZoneRecipes;
            return _resultValue;
        }
    }
}
