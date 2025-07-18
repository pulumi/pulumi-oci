// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.FleetAppsManagement.outputs.GetFleetResourcesFilter;
import com.pulumi.oci.FleetAppsManagement.outputs.GetFleetResourcesFleetResourceCollection;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetFleetResourcesResult {
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.  Example: `My new resource`
     * 
     */
    private @Nullable String displayName;
    private @Nullable List<GetFleetResourcesFilter> filters;
    private String fleetId;
    /**
     * @return The list of fleet_resource_collection.
     * 
     */
    private List<GetFleetResourcesFleetResourceCollection> fleetResourceCollections;
    private @Nullable String fleetResourceType;
    /**
     * @return The unique id of the resource.
     * 
     */
    private @Nullable String id;
    /**
     * @return The current state of the FleetResource.
     * 
     */
    private @Nullable String state;

    private GetFleetResourcesResult() {}
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.  Example: `My new resource`
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public List<GetFleetResourcesFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    public String fleetId() {
        return this.fleetId;
    }
    /**
     * @return The list of fleet_resource_collection.
     * 
     */
    public List<GetFleetResourcesFleetResourceCollection> fleetResourceCollections() {
        return this.fleetResourceCollections;
    }
    public Optional<String> fleetResourceType() {
        return Optional.ofNullable(this.fleetResourceType);
    }
    /**
     * @return The unique id of the resource.
     * 
     */
    public Optional<String> id() {
        return Optional.ofNullable(this.id);
    }
    /**
     * @return The current state of the FleetResource.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetFleetResourcesResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String displayName;
        private @Nullable List<GetFleetResourcesFilter> filters;
        private String fleetId;
        private List<GetFleetResourcesFleetResourceCollection> fleetResourceCollections;
        private @Nullable String fleetResourceType;
        private @Nullable String id;
        private @Nullable String state;
        public Builder() {}
        public Builder(GetFleetResourcesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.displayName = defaults.displayName;
    	      this.filters = defaults.filters;
    	      this.fleetId = defaults.fleetId;
    	      this.fleetResourceCollections = defaults.fleetResourceCollections;
    	      this.fleetResourceType = defaults.fleetResourceType;
    	      this.id = defaults.id;
    	      this.state = defaults.state;
        }

        @CustomType.Setter
        public Builder displayName(@Nullable String displayName) {

            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetFleetResourcesFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetFleetResourcesFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder fleetId(String fleetId) {
            if (fleetId == null) {
              throw new MissingRequiredPropertyException("GetFleetResourcesResult", "fleetId");
            }
            this.fleetId = fleetId;
            return this;
        }
        @CustomType.Setter
        public Builder fleetResourceCollections(List<GetFleetResourcesFleetResourceCollection> fleetResourceCollections) {
            if (fleetResourceCollections == null) {
              throw new MissingRequiredPropertyException("GetFleetResourcesResult", "fleetResourceCollections");
            }
            this.fleetResourceCollections = fleetResourceCollections;
            return this;
        }
        public Builder fleetResourceCollections(GetFleetResourcesFleetResourceCollection... fleetResourceCollections) {
            return fleetResourceCollections(List.of(fleetResourceCollections));
        }
        @CustomType.Setter
        public Builder fleetResourceType(@Nullable String fleetResourceType) {

            this.fleetResourceType = fleetResourceType;
            return this;
        }
        @CustomType.Setter
        public Builder id(@Nullable String id) {

            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {

            this.state = state;
            return this;
        }
        public GetFleetResourcesResult build() {
            final var _resultValue = new GetFleetResourcesResult();
            _resultValue.displayName = displayName;
            _resultValue.filters = filters;
            _resultValue.fleetId = fleetId;
            _resultValue.fleetResourceCollections = fleetResourceCollections;
            _resultValue.fleetResourceType = fleetResourceType;
            _resultValue.id = id;
            _resultValue.state = state;
            return _resultValue;
        }
    }
}
