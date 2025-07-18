// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetOnboardingsOnboardingCollectionItemAppliedPolicy {
    /**
     * @return Unique identifier or OCID for listing a single onboarding by id. Either compartmentId or id must be provided.
     * 
     */
    private String id;
    /**
     * @return Policy statements.
     * 
     */
    private List<String> statements;
    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    private Map<String,String> systemTags;
    /**
     * @return The time this resource was created. An RFC3339 formatted datetime string.
     * 
     */
    private String timeCreated;
    /**
     * @return The time this resource was last updated. An RFC3339 formatted datetime string.
     * 
     */
    private String timeUpdated;

    private GetOnboardingsOnboardingCollectionItemAppliedPolicy() {}
    /**
     * @return Unique identifier or OCID for listing a single onboarding by id. Either compartmentId or id must be provided.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Policy statements.
     * 
     */
    public List<String> statements() {
        return this.statements;
    }
    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Map<String,String> systemTags() {
        return this.systemTags;
    }
    /**
     * @return The time this resource was created. An RFC3339 formatted datetime string.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The time this resource was last updated. An RFC3339 formatted datetime string.
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetOnboardingsOnboardingCollectionItemAppliedPolicy defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String id;
        private List<String> statements;
        private Map<String,String> systemTags;
        private String timeCreated;
        private String timeUpdated;
        public Builder() {}
        public Builder(GetOnboardingsOnboardingCollectionItemAppliedPolicy defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.id = defaults.id;
    	      this.statements = defaults.statements;
    	      this.systemTags = defaults.systemTags;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
        }

        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetOnboardingsOnboardingCollectionItemAppliedPolicy", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder statements(List<String> statements) {
            if (statements == null) {
              throw new MissingRequiredPropertyException("GetOnboardingsOnboardingCollectionItemAppliedPolicy", "statements");
            }
            this.statements = statements;
            return this;
        }
        public Builder statements(String... statements) {
            return statements(List.of(statements));
        }
        @CustomType.Setter
        public Builder systemTags(Map<String,String> systemTags) {
            if (systemTags == null) {
              throw new MissingRequiredPropertyException("GetOnboardingsOnboardingCollectionItemAppliedPolicy", "systemTags");
            }
            this.systemTags = systemTags;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetOnboardingsOnboardingCollectionItemAppliedPolicy", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(String timeUpdated) {
            if (timeUpdated == null) {
              throw new MissingRequiredPropertyException("GetOnboardingsOnboardingCollectionItemAppliedPolicy", "timeUpdated");
            }
            this.timeUpdated = timeUpdated;
            return this;
        }
        public GetOnboardingsOnboardingCollectionItemAppliedPolicy build() {
            final var _resultValue = new GetOnboardingsOnboardingCollectionItemAppliedPolicy();
            _resultValue.id = id;
            _resultValue.statements = statements;
            _resultValue.systemTags = systemTags;
            _resultValue.timeCreated = timeCreated;
            _resultValue.timeUpdated = timeUpdated;
            return _resultValue;
        }
    }
}
