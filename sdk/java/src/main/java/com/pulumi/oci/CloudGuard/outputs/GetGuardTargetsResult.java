// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudGuard.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.CloudGuard.outputs.GetGuardTargetsFilter;
import com.pulumi.oci.CloudGuard.outputs.GetGuardTargetsTargetCollection;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetGuardTargetsResult {
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
    private @Nullable List<GetGuardTargetsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    private @Nullable Boolean isNonSecurityZoneTargetsOnlyQuery;
    /**
     * @return The current state of the ResponderRule.
     * 
     */
    private @Nullable String state;
    /**
     * @return The list of target_collection.
     * 
     */
    private List<GetGuardTargetsTargetCollection> targetCollections;

    private GetGuardTargetsResult() {}
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
    public List<GetGuardTargetsFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    public Optional<Boolean> isNonSecurityZoneTargetsOnlyQuery() {
        return Optional.ofNullable(this.isNonSecurityZoneTargetsOnlyQuery);
    }
    /**
     * @return The current state of the ResponderRule.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }
    /**
     * @return The list of target_collection.
     * 
     */
    public List<GetGuardTargetsTargetCollection> targetCollections() {
        return this.targetCollections;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetGuardTargetsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String accessLevel;
        private String compartmentId;
        private @Nullable Boolean compartmentIdInSubtree;
        private @Nullable String displayName;
        private @Nullable List<GetGuardTargetsFilter> filters;
        private String id;
        private @Nullable Boolean isNonSecurityZoneTargetsOnlyQuery;
        private @Nullable String state;
        private List<GetGuardTargetsTargetCollection> targetCollections;
        public Builder() {}
        public Builder(GetGuardTargetsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.accessLevel = defaults.accessLevel;
    	      this.compartmentId = defaults.compartmentId;
    	      this.compartmentIdInSubtree = defaults.compartmentIdInSubtree;
    	      this.displayName = defaults.displayName;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.isNonSecurityZoneTargetsOnlyQuery = defaults.isNonSecurityZoneTargetsOnlyQuery;
    	      this.state = defaults.state;
    	      this.targetCollections = defaults.targetCollections;
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
        public Builder filters(@Nullable List<GetGuardTargetsFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetGuardTargetsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder isNonSecurityZoneTargetsOnlyQuery(@Nullable Boolean isNonSecurityZoneTargetsOnlyQuery) {
            this.isNonSecurityZoneTargetsOnlyQuery = isNonSecurityZoneTargetsOnlyQuery;
            return this;
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder targetCollections(List<GetGuardTargetsTargetCollection> targetCollections) {
            this.targetCollections = Objects.requireNonNull(targetCollections);
            return this;
        }
        public Builder targetCollections(GetGuardTargetsTargetCollection... targetCollections) {
            return targetCollections(List.of(targetCollections));
        }
        public GetGuardTargetsResult build() {
            final var o = new GetGuardTargetsResult();
            o.accessLevel = accessLevel;
            o.compartmentId = compartmentId;
            o.compartmentIdInSubtree = compartmentIdInSubtree;
            o.displayName = displayName;
            o.filters = filters;
            o.id = id;
            o.isNonSecurityZoneTargetsOnlyQuery = isNonSecurityZoneTargetsOnlyQuery;
            o.state = state;
            o.targetCollections = targetCollections;
            return o;
        }
    }
}