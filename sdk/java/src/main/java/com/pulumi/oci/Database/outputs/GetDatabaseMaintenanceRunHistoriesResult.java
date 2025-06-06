// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Database.outputs.GetDatabaseMaintenanceRunHistoriesFilter;
import com.pulumi.oci.Database.outputs.GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistory;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetDatabaseMaintenanceRunHistoriesResult {
    private @Nullable String availabilityDomain;
    /**
     * @return The OCID of the compartment.
     * 
     */
    private String compartmentId;
    private @Nullable List<GetDatabaseMaintenanceRunHistoriesFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The list of maintenance_run_histories.
     * 
     */
    private List<GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistory> maintenanceRunHistories;
    /**
     * @return Maintenance type.
     * 
     */
    private @Nullable String maintenanceType;
    /**
     * @return The current state of the maintenance run. For Autonomous Database Serverless instances, valid states are IN_PROGRESS, SUCCEEDED, and FAILED.
     * 
     */
    private @Nullable String state;
    /**
     * @return The ID of the target resource on which the maintenance run occurs.
     * 
     */
    private @Nullable String targetResourceId;
    /**
     * @return The type of the target resource on which the maintenance run occurs.
     * 
     */
    private @Nullable String targetResourceType;

    private GetDatabaseMaintenanceRunHistoriesResult() {}
    public Optional<String> availabilityDomain() {
        return Optional.ofNullable(this.availabilityDomain);
    }
    /**
     * @return The OCID of the compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    public List<GetDatabaseMaintenanceRunHistoriesFilter> filters() {
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
     * @return The list of maintenance_run_histories.
     * 
     */
    public List<GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistory> maintenanceRunHistories() {
        return this.maintenanceRunHistories;
    }
    /**
     * @return Maintenance type.
     * 
     */
    public Optional<String> maintenanceType() {
        return Optional.ofNullable(this.maintenanceType);
    }
    /**
     * @return The current state of the maintenance run. For Autonomous Database Serverless instances, valid states are IN_PROGRESS, SUCCEEDED, and FAILED.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }
    /**
     * @return The ID of the target resource on which the maintenance run occurs.
     * 
     */
    public Optional<String> targetResourceId() {
        return Optional.ofNullable(this.targetResourceId);
    }
    /**
     * @return The type of the target resource on which the maintenance run occurs.
     * 
     */
    public Optional<String> targetResourceType() {
        return Optional.ofNullable(this.targetResourceType);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDatabaseMaintenanceRunHistoriesResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String availabilityDomain;
        private String compartmentId;
        private @Nullable List<GetDatabaseMaintenanceRunHistoriesFilter> filters;
        private String id;
        private List<GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistory> maintenanceRunHistories;
        private @Nullable String maintenanceType;
        private @Nullable String state;
        private @Nullable String targetResourceId;
        private @Nullable String targetResourceType;
        public Builder() {}
        public Builder(GetDatabaseMaintenanceRunHistoriesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.availabilityDomain = defaults.availabilityDomain;
    	      this.compartmentId = defaults.compartmentId;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.maintenanceRunHistories = defaults.maintenanceRunHistories;
    	      this.maintenanceType = defaults.maintenanceType;
    	      this.state = defaults.state;
    	      this.targetResourceId = defaults.targetResourceId;
    	      this.targetResourceType = defaults.targetResourceType;
        }

        @CustomType.Setter
        public Builder availabilityDomain(@Nullable String availabilityDomain) {

            this.availabilityDomain = availabilityDomain;
            return this;
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetDatabaseMaintenanceRunHistoriesResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetDatabaseMaintenanceRunHistoriesFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetDatabaseMaintenanceRunHistoriesFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetDatabaseMaintenanceRunHistoriesResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder maintenanceRunHistories(List<GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistory> maintenanceRunHistories) {
            if (maintenanceRunHistories == null) {
              throw new MissingRequiredPropertyException("GetDatabaseMaintenanceRunHistoriesResult", "maintenanceRunHistories");
            }
            this.maintenanceRunHistories = maintenanceRunHistories;
            return this;
        }
        public Builder maintenanceRunHistories(GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistory... maintenanceRunHistories) {
            return maintenanceRunHistories(List.of(maintenanceRunHistories));
        }
        @CustomType.Setter
        public Builder maintenanceType(@Nullable String maintenanceType) {

            this.maintenanceType = maintenanceType;
            return this;
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {

            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder targetResourceId(@Nullable String targetResourceId) {

            this.targetResourceId = targetResourceId;
            return this;
        }
        @CustomType.Setter
        public Builder targetResourceType(@Nullable String targetResourceType) {

            this.targetResourceType = targetResourceType;
            return this;
        }
        public GetDatabaseMaintenanceRunHistoriesResult build() {
            final var _resultValue = new GetDatabaseMaintenanceRunHistoriesResult();
            _resultValue.availabilityDomain = availabilityDomain;
            _resultValue.compartmentId = compartmentId;
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.maintenanceRunHistories = maintenanceRunHistories;
            _resultValue.maintenanceType = maintenanceType;
            _resultValue.state = state;
            _resultValue.targetResourceId = targetResourceId;
            _resultValue.targetResourceType = targetResourceType;
            return _resultValue;
        }
    }
}
