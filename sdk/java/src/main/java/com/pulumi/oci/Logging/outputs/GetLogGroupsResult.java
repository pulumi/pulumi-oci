// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Logging.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Logging.outputs.GetLogGroupsFilter;
import com.pulumi.oci.Logging.outputs.GetLogGroupsLogGroup;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetLogGroupsResult {
    /**
     * @return The OCID of the compartment that the resource belongs to.
     * 
     */
    private String compartmentId;
    /**
     * @return The user-friendly display name. This must be unique within the enclosing resource, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    private @Nullable String displayName;
    private @Nullable List<GetLogGroupsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    private @Nullable Boolean isCompartmentIdInSubtree;
    /**
     * @return The list of log_groups.
     * 
     */
    private List<GetLogGroupsLogGroup> logGroups;

    private GetLogGroupsResult() {}
    /**
     * @return The OCID of the compartment that the resource belongs to.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The user-friendly display name. This must be unique within the enclosing resource, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public List<GetLogGroupsFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    public Optional<Boolean> isCompartmentIdInSubtree() {
        return Optional.ofNullable(this.isCompartmentIdInSubtree);
    }
    /**
     * @return The list of log_groups.
     * 
     */
    public List<GetLogGroupsLogGroup> logGroups() {
        return this.logGroups;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetLogGroupsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private @Nullable String displayName;
        private @Nullable List<GetLogGroupsFilter> filters;
        private String id;
        private @Nullable Boolean isCompartmentIdInSubtree;
        private List<GetLogGroupsLogGroup> logGroups;
        public Builder() {}
        public Builder(GetLogGroupsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.displayName = defaults.displayName;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.isCompartmentIdInSubtree = defaults.isCompartmentIdInSubtree;
    	      this.logGroups = defaults.logGroups;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder displayName(@Nullable String displayName) {
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetLogGroupsFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetLogGroupsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder isCompartmentIdInSubtree(@Nullable Boolean isCompartmentIdInSubtree) {
            this.isCompartmentIdInSubtree = isCompartmentIdInSubtree;
            return this;
        }
        @CustomType.Setter
        public Builder logGroups(List<GetLogGroupsLogGroup> logGroups) {
            this.logGroups = Objects.requireNonNull(logGroups);
            return this;
        }
        public Builder logGroups(GetLogGroupsLogGroup... logGroups) {
            return logGroups(List.of(logGroups));
        }
        public GetLogGroupsResult build() {
            final var o = new GetLogGroupsResult();
            o.compartmentId = compartmentId;
            o.displayName = displayName;
            o.filters = filters;
            o.id = id;
            o.isCompartmentIdInSubtree = isCompartmentIdInSubtree;
            o.logGroups = logGroups;
            return o;
        }
    }
}