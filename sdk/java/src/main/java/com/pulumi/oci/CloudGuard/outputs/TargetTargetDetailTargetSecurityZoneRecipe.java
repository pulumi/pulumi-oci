// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudGuard.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class TargetTargetDetailTargetSecurityZoneRecipe {
    /**
     * @return (Updatable) compartment associated with condition
     * 
     */
    private @Nullable String compartmentId;
    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private @Nullable Map<String,Object> definedTags;
    /**
     * @return The target description.
     * 
     */
    private @Nullable String description;
    /**
     * @return (Updatable) DetectorTemplate identifier.
     * 
     */
    private @Nullable String displayName;
    /**
     * @return (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private @Nullable Map<String,Object> freeformTags;
    /**
     * @return Unique identifier of TargetResponderRecipe that can&#39;t be changed after creation.
     * 
     */
    private @Nullable String id;
    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     * 
     */
    private @Nullable String lifecycleDetails;
    /**
     * @return Owner of ResponderRecipe
     * 
     */
    private @Nullable String owner;
    /**
     * @return The list of `SecurityPolicy` ids that are included in the recipe
     * 
     */
    private @Nullable List<String> securityPolicies;
    /**
     * @return (Updatable) The current state of the DetectorRule.
     * 
     */
    private @Nullable String state;
    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    private @Nullable Map<String,Object> systemTags;
    /**
     * @return The date and time the target was created. Format defined by RFC3339.
     * 
     */
    private @Nullable String timeCreated;
    /**
     * @return The date and time the target was updated. Format defined by RFC3339.
     * 
     */
    private @Nullable String timeUpdated;

    private TargetTargetDetailTargetSecurityZoneRecipe() {}
    /**
     * @return (Updatable) compartment associated with condition
     * 
     */
    public Optional<String> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }
    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,Object> definedTags() {
        return this.definedTags == null ? Map.of() : this.definedTags;
    }
    /**
     * @return The target description.
     * 
     */
    public Optional<String> description() {
        return Optional.ofNullable(this.description);
    }
    /**
     * @return (Updatable) DetectorTemplate identifier.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    /**
     * @return (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,Object> freeformTags() {
        return this.freeformTags == null ? Map.of() : this.freeformTags;
    }
    /**
     * @return Unique identifier of TargetResponderRecipe that can&#39;t be changed after creation.
     * 
     */
    public Optional<String> id() {
        return Optional.ofNullable(this.id);
    }
    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     * 
     */
    public Optional<String> lifecycleDetails() {
        return Optional.ofNullable(this.lifecycleDetails);
    }
    /**
     * @return Owner of ResponderRecipe
     * 
     */
    public Optional<String> owner() {
        return Optional.ofNullable(this.owner);
    }
    /**
     * @return The list of `SecurityPolicy` ids that are included in the recipe
     * 
     */
    public List<String> securityPolicies() {
        return this.securityPolicies == null ? List.of() : this.securityPolicies;
    }
    /**
     * @return (Updatable) The current state of the DetectorRule.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }
    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Map<String,Object> systemTags() {
        return this.systemTags == null ? Map.of() : this.systemTags;
    }
    /**
     * @return The date and time the target was created. Format defined by RFC3339.
     * 
     */
    public Optional<String> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }
    /**
     * @return The date and time the target was updated. Format defined by RFC3339.
     * 
     */
    public Optional<String> timeUpdated() {
        return Optional.ofNullable(this.timeUpdated);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(TargetTargetDetailTargetSecurityZoneRecipe defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String compartmentId;
        private @Nullable Map<String,Object> definedTags;
        private @Nullable String description;
        private @Nullable String displayName;
        private @Nullable Map<String,Object> freeformTags;
        private @Nullable String id;
        private @Nullable String lifecycleDetails;
        private @Nullable String owner;
        private @Nullable List<String> securityPolicies;
        private @Nullable String state;
        private @Nullable Map<String,Object> systemTags;
        private @Nullable String timeCreated;
        private @Nullable String timeUpdated;
        public Builder() {}
        public Builder(TargetTargetDetailTargetSecurityZoneRecipe defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.definedTags = defaults.definedTags;
    	      this.description = defaults.description;
    	      this.displayName = defaults.displayName;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.owner = defaults.owner;
    	      this.securityPolicies = defaults.securityPolicies;
    	      this.state = defaults.state;
    	      this.systemTags = defaults.systemTags;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
        }

        @CustomType.Setter
        public Builder compartmentId(@Nullable String compartmentId) {
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(@Nullable Map<String,Object> definedTags) {
            this.definedTags = definedTags;
            return this;
        }
        @CustomType.Setter
        public Builder description(@Nullable String description) {
            this.description = description;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(@Nullable String displayName) {
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(@Nullable Map<String,Object> freeformTags) {
            this.freeformTags = freeformTags;
            return this;
        }
        @CustomType.Setter
        public Builder id(@Nullable String id) {
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder lifecycleDetails(@Nullable String lifecycleDetails) {
            this.lifecycleDetails = lifecycleDetails;
            return this;
        }
        @CustomType.Setter
        public Builder owner(@Nullable String owner) {
            this.owner = owner;
            return this;
        }
        @CustomType.Setter
        public Builder securityPolicies(@Nullable List<String> securityPolicies) {
            this.securityPolicies = securityPolicies;
            return this;
        }
        public Builder securityPolicies(String... securityPolicies) {
            return securityPolicies(List.of(securityPolicies));
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder systemTags(@Nullable Map<String,Object> systemTags) {
            this.systemTags = systemTags;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(@Nullable String timeCreated) {
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(@Nullable String timeUpdated) {
            this.timeUpdated = timeUpdated;
            return this;
        }
        public TargetTargetDetailTargetSecurityZoneRecipe build() {
            final var o = new TargetTargetDetailTargetSecurityZoneRecipe();
            o.compartmentId = compartmentId;
            o.definedTags = definedTags;
            o.description = description;
            o.displayName = displayName;
            o.freeformTags = freeformTags;
            o.id = id;
            o.lifecycleDetails = lifecycleDetails;
            o.owner = owner;
            o.securityPolicies = securityPolicies;
            o.state = state;
            o.systemTags = systemTags;
            o.timeCreated = timeCreated;
            o.timeUpdated = timeUpdated;
            return o;
        }
    }
}