// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudMigrations.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.CloudMigrations.outputs.GetMigrationPlanAvailableShapesAvailableShapesCollection;
import com.pulumi.oci.CloudMigrations.outputs.GetMigrationPlanAvailableShapesFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetMigrationPlanAvailableShapesResult {
    /**
     * @return Availability domain of the shape.
     * 
     */
    private @Nullable String availabilityDomain;
    /**
     * @return The list of available_shapes_collection.
     * 
     */
    private List<GetMigrationPlanAvailableShapesAvailableShapesCollection> availableShapesCollections;
    private @Nullable String compartmentId;
    private @Nullable String dvhHostId;
    private @Nullable List<GetMigrationPlanAvailableShapesFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    private String migrationPlanId;
    private @Nullable String reservedCapacityId;

    private GetMigrationPlanAvailableShapesResult() {}
    /**
     * @return Availability domain of the shape.
     * 
     */
    public Optional<String> availabilityDomain() {
        return Optional.ofNullable(this.availabilityDomain);
    }
    /**
     * @return The list of available_shapes_collection.
     * 
     */
    public List<GetMigrationPlanAvailableShapesAvailableShapesCollection> availableShapesCollections() {
        return this.availableShapesCollections;
    }
    public Optional<String> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }
    public Optional<String> dvhHostId() {
        return Optional.ofNullable(this.dvhHostId);
    }
    public List<GetMigrationPlanAvailableShapesFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    public String migrationPlanId() {
        return this.migrationPlanId;
    }
    public Optional<String> reservedCapacityId() {
        return Optional.ofNullable(this.reservedCapacityId);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetMigrationPlanAvailableShapesResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String availabilityDomain;
        private List<GetMigrationPlanAvailableShapesAvailableShapesCollection> availableShapesCollections;
        private @Nullable String compartmentId;
        private @Nullable String dvhHostId;
        private @Nullable List<GetMigrationPlanAvailableShapesFilter> filters;
        private String id;
        private String migrationPlanId;
        private @Nullable String reservedCapacityId;
        public Builder() {}
        public Builder(GetMigrationPlanAvailableShapesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.availabilityDomain = defaults.availabilityDomain;
    	      this.availableShapesCollections = defaults.availableShapesCollections;
    	      this.compartmentId = defaults.compartmentId;
    	      this.dvhHostId = defaults.dvhHostId;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.migrationPlanId = defaults.migrationPlanId;
    	      this.reservedCapacityId = defaults.reservedCapacityId;
        }

        @CustomType.Setter
        public Builder availabilityDomain(@Nullable String availabilityDomain) {
            this.availabilityDomain = availabilityDomain;
            return this;
        }
        @CustomType.Setter
        public Builder availableShapesCollections(List<GetMigrationPlanAvailableShapesAvailableShapesCollection> availableShapesCollections) {
            this.availableShapesCollections = Objects.requireNonNull(availableShapesCollections);
            return this;
        }
        public Builder availableShapesCollections(GetMigrationPlanAvailableShapesAvailableShapesCollection... availableShapesCollections) {
            return availableShapesCollections(List.of(availableShapesCollections));
        }
        @CustomType.Setter
        public Builder compartmentId(@Nullable String compartmentId) {
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder dvhHostId(@Nullable String dvhHostId) {
            this.dvhHostId = dvhHostId;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetMigrationPlanAvailableShapesFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetMigrationPlanAvailableShapesFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder migrationPlanId(String migrationPlanId) {
            this.migrationPlanId = Objects.requireNonNull(migrationPlanId);
            return this;
        }
        @CustomType.Setter
        public Builder reservedCapacityId(@Nullable String reservedCapacityId) {
            this.reservedCapacityId = reservedCapacityId;
            return this;
        }
        public GetMigrationPlanAvailableShapesResult build() {
            final var o = new GetMigrationPlanAvailableShapesResult();
            o.availabilityDomain = availabilityDomain;
            o.availableShapesCollections = availableShapesCollections;
            o.compartmentId = compartmentId;
            o.dvhHostId = dvhHostId;
            o.filters = filters;
            o.id = id;
            o.migrationPlanId = migrationPlanId;
            o.reservedCapacityId = reservedCapacityId;
            return o;
        }
    }
}