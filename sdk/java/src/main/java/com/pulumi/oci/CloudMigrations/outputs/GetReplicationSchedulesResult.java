// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudMigrations.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.CloudMigrations.outputs.GetReplicationSchedulesFilter;
import com.pulumi.oci.CloudMigrations.outputs.GetReplicationSchedulesReplicationScheduleCollection;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetReplicationSchedulesResult {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the replication schedule exists.
     * 
     */
    private @Nullable String compartmentId;
    /**
     * @return A name of the replication schedule.
     * 
     */
    private @Nullable String displayName;
    private @Nullable List<GetReplicationSchedulesFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The list of replication_schedule_collection.
     * 
     */
    private List<GetReplicationSchedulesReplicationScheduleCollection> replicationScheduleCollections;
    private @Nullable String replicationScheduleId;
    /**
     * @return Current state of the replication schedule.
     * 
     */
    private @Nullable String state;

    private GetReplicationSchedulesResult() {}
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the replication schedule exists.
     * 
     */
    public Optional<String> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }
    /**
     * @return A name of the replication schedule.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public List<GetReplicationSchedulesFilter> filters() {
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
     * @return The list of replication_schedule_collection.
     * 
     */
    public List<GetReplicationSchedulesReplicationScheduleCollection> replicationScheduleCollections() {
        return this.replicationScheduleCollections;
    }
    public Optional<String> replicationScheduleId() {
        return Optional.ofNullable(this.replicationScheduleId);
    }
    /**
     * @return Current state of the replication schedule.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetReplicationSchedulesResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String compartmentId;
        private @Nullable String displayName;
        private @Nullable List<GetReplicationSchedulesFilter> filters;
        private String id;
        private List<GetReplicationSchedulesReplicationScheduleCollection> replicationScheduleCollections;
        private @Nullable String replicationScheduleId;
        private @Nullable String state;
        public Builder() {}
        public Builder(GetReplicationSchedulesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.displayName = defaults.displayName;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.replicationScheduleCollections = defaults.replicationScheduleCollections;
    	      this.replicationScheduleId = defaults.replicationScheduleId;
    	      this.state = defaults.state;
        }

        @CustomType.Setter
        public Builder compartmentId(@Nullable String compartmentId) {
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(@Nullable String displayName) {
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetReplicationSchedulesFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetReplicationSchedulesFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder replicationScheduleCollections(List<GetReplicationSchedulesReplicationScheduleCollection> replicationScheduleCollections) {
            this.replicationScheduleCollections = Objects.requireNonNull(replicationScheduleCollections);
            return this;
        }
        public Builder replicationScheduleCollections(GetReplicationSchedulesReplicationScheduleCollection... replicationScheduleCollections) {
            return replicationScheduleCollections(List.of(replicationScheduleCollections));
        }
        @CustomType.Setter
        public Builder replicationScheduleId(@Nullable String replicationScheduleId) {
            this.replicationScheduleId = replicationScheduleId;
            return this;
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {
            this.state = state;
            return this;
        }
        public GetReplicationSchedulesResult build() {
            final var o = new GetReplicationSchedulesResult();
            o.compartmentId = compartmentId;
            o.displayName = displayName;
            o.filters = filters;
            o.id = id;
            o.replicationScheduleCollections = replicationScheduleCollections;
            o.replicationScheduleId = replicationScheduleId;
            o.state = state;
            return o;
        }
    }
}