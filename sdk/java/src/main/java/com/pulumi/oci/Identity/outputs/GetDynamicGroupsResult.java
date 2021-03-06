// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Identity.outputs.GetDynamicGroupsDynamicGroup;
import com.pulumi.oci.Identity.outputs.GetDynamicGroupsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetDynamicGroupsResult {
    /**
     * @return The OCID of the tenancy containing the group.
     * 
     */
    private final String compartmentId;
    /**
     * @return The list of dynamic_groups.
     * 
     */
    private final List<GetDynamicGroupsDynamicGroup> dynamicGroups;
    private final @Nullable List<GetDynamicGroupsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private final String id;
    /**
     * @return The name you assign to the group during creation. The name must be unique across all groups in the tenancy and cannot be changed.
     * 
     */
    private final @Nullable String name;
    /**
     * @return The group&#39;s current state.
     * 
     */
    private final @Nullable String state;

    @CustomType.Constructor
    private GetDynamicGroupsResult(
        @CustomType.Parameter("compartmentId") String compartmentId,
        @CustomType.Parameter("dynamicGroups") List<GetDynamicGroupsDynamicGroup> dynamicGroups,
        @CustomType.Parameter("filters") @Nullable List<GetDynamicGroupsFilter> filters,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("name") @Nullable String name,
        @CustomType.Parameter("state") @Nullable String state) {
        this.compartmentId = compartmentId;
        this.dynamicGroups = dynamicGroups;
        this.filters = filters;
        this.id = id;
        this.name = name;
        this.state = state;
    }

    /**
     * @return The OCID of the tenancy containing the group.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The list of dynamic_groups.
     * 
     */
    public List<GetDynamicGroupsDynamicGroup> dynamicGroups() {
        return this.dynamicGroups;
    }
    public List<GetDynamicGroupsFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The name you assign to the group during creation. The name must be unique across all groups in the tenancy and cannot be changed.
     * 
     */
    public Optional<String> name() {
        return Optional.ofNullable(this.name);
    }
    /**
     * @return The group&#39;s current state.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDynamicGroupsResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String compartmentId;
        private List<GetDynamicGroupsDynamicGroup> dynamicGroups;
        private @Nullable List<GetDynamicGroupsFilter> filters;
        private String id;
        private @Nullable String name;
        private @Nullable String state;

        public Builder() {
    	      // Empty
        }

        public Builder(GetDynamicGroupsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.dynamicGroups = defaults.dynamicGroups;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.name = defaults.name;
    	      this.state = defaults.state;
        }

        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        public Builder dynamicGroups(List<GetDynamicGroupsDynamicGroup> dynamicGroups) {
            this.dynamicGroups = Objects.requireNonNull(dynamicGroups);
            return this;
        }
        public Builder dynamicGroups(GetDynamicGroupsDynamicGroup... dynamicGroups) {
            return dynamicGroups(List.of(dynamicGroups));
        }
        public Builder filters(@Nullable List<GetDynamicGroupsFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetDynamicGroupsFilter... filters) {
            return filters(List.of(filters));
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder name(@Nullable String name) {
            this.name = name;
            return this;
        }
        public Builder state(@Nullable String state) {
            this.state = state;
            return this;
        }        public GetDynamicGroupsResult build() {
            return new GetDynamicGroupsResult(compartmentId, dynamicGroups, filters, id, name, state);
        }
    }
}
