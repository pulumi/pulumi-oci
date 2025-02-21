// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudGuard.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDetectorRecipesDetectorRecipeCollectionItemEffectiveDetectorRuleCandidateResponderRule {
    /**
     * @return A filter to return only resources that match the entire display name given.
     * 
     */
    private String displayName;
    /**
     * @return OCID for detector recipe
     * 
     */
    private String id;
    /**
     * @return Is this the preferred state?
     * 
     */
    private Boolean isPreferred;

    private GetDetectorRecipesDetectorRecipeCollectionItemEffectiveDetectorRuleCandidateResponderRule() {}
    /**
     * @return A filter to return only resources that match the entire display name given.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return OCID for detector recipe
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Is this the preferred state?
     * 
     */
    public Boolean isPreferred() {
        return this.isPreferred;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDetectorRecipesDetectorRecipeCollectionItemEffectiveDetectorRuleCandidateResponderRule defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String displayName;
        private String id;
        private Boolean isPreferred;
        public Builder() {}
        public Builder(GetDetectorRecipesDetectorRecipeCollectionItemEffectiveDetectorRuleCandidateResponderRule defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.displayName = defaults.displayName;
    	      this.id = defaults.id;
    	      this.isPreferred = defaults.isPreferred;
        }

        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetDetectorRecipesDetectorRecipeCollectionItemEffectiveDetectorRuleCandidateResponderRule", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetDetectorRecipesDetectorRecipeCollectionItemEffectiveDetectorRuleCandidateResponderRule", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder isPreferred(Boolean isPreferred) {
            if (isPreferred == null) {
              throw new MissingRequiredPropertyException("GetDetectorRecipesDetectorRecipeCollectionItemEffectiveDetectorRuleCandidateResponderRule", "isPreferred");
            }
            this.isPreferred = isPreferred;
            return this;
        }
        public GetDetectorRecipesDetectorRecipeCollectionItemEffectiveDetectorRuleCandidateResponderRule build() {
            final var _resultValue = new GetDetectorRecipesDetectorRecipeCollectionItemEffectiveDetectorRuleCandidateResponderRule();
            _resultValue.displayName = displayName;
            _resultValue.id = id;
            _resultValue.isPreferred = isPreferred;
            return _resultValue;
        }
    }
}
