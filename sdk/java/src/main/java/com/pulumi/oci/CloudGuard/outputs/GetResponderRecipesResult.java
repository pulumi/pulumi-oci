// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudGuard.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.CloudGuard.outputs.GetResponderRecipesFilter;
import com.pulumi.oci.CloudGuard.outputs.GetResponderRecipesResponderRecipeCollection;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetResponderRecipesResult {
    private @Nullable String accessLevel;
    /**
     * @return Compartment Identifier
     * 
     */
    private String compartmentId;
    private @Nullable Boolean compartmentIdInSubtree;
    /**
     * @return ResponderRule display name.
     * 
     */
    private @Nullable String displayName;
    private @Nullable List<GetResponderRecipesFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    private @Nullable Boolean resourceMetadataOnly;
    /**
     * @return The list of responder_recipe_collection.
     * 
     */
    private List<GetResponderRecipesResponderRecipeCollection> responderRecipeCollections;
    /**
     * @return The current state of the Example.
     * 
     */
    private @Nullable String state;

    private GetResponderRecipesResult() {}
    public Optional<String> accessLevel() {
        return Optional.ofNullable(this.accessLevel);
    }
    /**
     * @return Compartment Identifier
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    public Optional<Boolean> compartmentIdInSubtree() {
        return Optional.ofNullable(this.compartmentIdInSubtree);
    }
    /**
     * @return ResponderRule display name.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public List<GetResponderRecipesFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    public Optional<Boolean> resourceMetadataOnly() {
        return Optional.ofNullable(this.resourceMetadataOnly);
    }
    /**
     * @return The list of responder_recipe_collection.
     * 
     */
    public List<GetResponderRecipesResponderRecipeCollection> responderRecipeCollections() {
        return this.responderRecipeCollections;
    }
    /**
     * @return The current state of the Example.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetResponderRecipesResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String accessLevel;
        private String compartmentId;
        private @Nullable Boolean compartmentIdInSubtree;
        private @Nullable String displayName;
        private @Nullable List<GetResponderRecipesFilter> filters;
        private String id;
        private @Nullable Boolean resourceMetadataOnly;
        private List<GetResponderRecipesResponderRecipeCollection> responderRecipeCollections;
        private @Nullable String state;
        public Builder() {}
        public Builder(GetResponderRecipesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.accessLevel = defaults.accessLevel;
    	      this.compartmentId = defaults.compartmentId;
    	      this.compartmentIdInSubtree = defaults.compartmentIdInSubtree;
    	      this.displayName = defaults.displayName;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.resourceMetadataOnly = defaults.resourceMetadataOnly;
    	      this.responderRecipeCollections = defaults.responderRecipeCollections;
    	      this.state = defaults.state;
        }

        @CustomType.Setter
        public Builder accessLevel(@Nullable String accessLevel) {
            this.accessLevel = accessLevel;
            return this;
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder compartmentIdInSubtree(@Nullable Boolean compartmentIdInSubtree) {
            this.compartmentIdInSubtree = compartmentIdInSubtree;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(@Nullable String displayName) {
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetResponderRecipesFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetResponderRecipesFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder resourceMetadataOnly(@Nullable Boolean resourceMetadataOnly) {
            this.resourceMetadataOnly = resourceMetadataOnly;
            return this;
        }
        @CustomType.Setter
        public Builder responderRecipeCollections(List<GetResponderRecipesResponderRecipeCollection> responderRecipeCollections) {
            this.responderRecipeCollections = Objects.requireNonNull(responderRecipeCollections);
            return this;
        }
        public Builder responderRecipeCollections(GetResponderRecipesResponderRecipeCollection... responderRecipeCollections) {
            return responderRecipeCollections(List.of(responderRecipeCollections));
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {
            this.state = state;
            return this;
        }
        public GetResponderRecipesResult build() {
            final var o = new GetResponderRecipesResult();
            o.accessLevel = accessLevel;
            o.compartmentId = compartmentId;
            o.compartmentIdInSubtree = compartmentIdInSubtree;
            o.displayName = displayName;
            o.filters = filters;
            o.id = id;
            o.resourceMetadataOnly = resourceMetadataOnly;
            o.responderRecipeCollections = responderRecipeCollections;
            o.state = state;
            return o;
        }
    }
}