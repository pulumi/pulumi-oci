// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Jms.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Jms.outputs.GetFleetJavaMigrationAnalysisResultsFilter;
import com.pulumi.oci.Jms.outputs.GetFleetJavaMigrationAnalysisResultsJavaMigrationAnalysisResultCollection;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetFleetJavaMigrationAnalysisResultsResult {
    private @Nullable List<GetFleetJavaMigrationAnalysisResultsFilter> filters;
    /**
     * @return The fleet OCID.
     * 
     */
    private String fleetId;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The list of java_migration_analysis_result_collection.
     * 
     */
    private List<GetFleetJavaMigrationAnalysisResultsJavaMigrationAnalysisResultCollection> javaMigrationAnalysisResultCollections;
    /**
     * @return The managed instance OCID.
     * 
     */
    private @Nullable String managedInstanceId;
    private @Nullable String timeEnd;
    private @Nullable String timeStart;

    private GetFleetJavaMigrationAnalysisResultsResult() {}
    public List<GetFleetJavaMigrationAnalysisResultsFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The fleet OCID.
     * 
     */
    public String fleetId() {
        return this.fleetId;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The list of java_migration_analysis_result_collection.
     * 
     */
    public List<GetFleetJavaMigrationAnalysisResultsJavaMigrationAnalysisResultCollection> javaMigrationAnalysisResultCollections() {
        return this.javaMigrationAnalysisResultCollections;
    }
    /**
     * @return The managed instance OCID.
     * 
     */
    public Optional<String> managedInstanceId() {
        return Optional.ofNullable(this.managedInstanceId);
    }
    public Optional<String> timeEnd() {
        return Optional.ofNullable(this.timeEnd);
    }
    public Optional<String> timeStart() {
        return Optional.ofNullable(this.timeStart);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetFleetJavaMigrationAnalysisResultsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable List<GetFleetJavaMigrationAnalysisResultsFilter> filters;
        private String fleetId;
        private String id;
        private List<GetFleetJavaMigrationAnalysisResultsJavaMigrationAnalysisResultCollection> javaMigrationAnalysisResultCollections;
        private @Nullable String managedInstanceId;
        private @Nullable String timeEnd;
        private @Nullable String timeStart;
        public Builder() {}
        public Builder(GetFleetJavaMigrationAnalysisResultsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.filters = defaults.filters;
    	      this.fleetId = defaults.fleetId;
    	      this.id = defaults.id;
    	      this.javaMigrationAnalysisResultCollections = defaults.javaMigrationAnalysisResultCollections;
    	      this.managedInstanceId = defaults.managedInstanceId;
    	      this.timeEnd = defaults.timeEnd;
    	      this.timeStart = defaults.timeStart;
        }

        @CustomType.Setter
        public Builder filters(@Nullable List<GetFleetJavaMigrationAnalysisResultsFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetFleetJavaMigrationAnalysisResultsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder fleetId(String fleetId) {
            this.fleetId = Objects.requireNonNull(fleetId);
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder javaMigrationAnalysisResultCollections(List<GetFleetJavaMigrationAnalysisResultsJavaMigrationAnalysisResultCollection> javaMigrationAnalysisResultCollections) {
            this.javaMigrationAnalysisResultCollections = Objects.requireNonNull(javaMigrationAnalysisResultCollections);
            return this;
        }
        public Builder javaMigrationAnalysisResultCollections(GetFleetJavaMigrationAnalysisResultsJavaMigrationAnalysisResultCollection... javaMigrationAnalysisResultCollections) {
            return javaMigrationAnalysisResultCollections(List.of(javaMigrationAnalysisResultCollections));
        }
        @CustomType.Setter
        public Builder managedInstanceId(@Nullable String managedInstanceId) {
            this.managedInstanceId = managedInstanceId;
            return this;
        }
        @CustomType.Setter
        public Builder timeEnd(@Nullable String timeEnd) {
            this.timeEnd = timeEnd;
            return this;
        }
        @CustomType.Setter
        public Builder timeStart(@Nullable String timeStart) {
            this.timeStart = timeStart;
            return this;
        }
        public GetFleetJavaMigrationAnalysisResultsResult build() {
            final var o = new GetFleetJavaMigrationAnalysisResultsResult();
            o.filters = filters;
            o.fleetId = fleetId;
            o.id = id;
            o.javaMigrationAnalysisResultCollections = javaMigrationAnalysisResultCollections;
            o.managedInstanceId = managedInstanceId;
            o.timeEnd = timeEnd;
            o.timeStart = timeStart;
            return o;
        }
    }
}