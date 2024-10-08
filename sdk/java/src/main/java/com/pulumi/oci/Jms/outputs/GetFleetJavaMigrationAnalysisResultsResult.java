// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Jms.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Jms.outputs.GetFleetJavaMigrationAnalysisResultsFilter;
import com.pulumi.oci.Jms.outputs.GetFleetJavaMigrationAnalysisResultsJavaMigrationAnalysisResultCollection;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetFleetJavaMigrationAnalysisResultsResult {
    /**
     * @return The name of the application for which the Java migration analysis was performed.
     * 
     */
    private @Nullable String applicationName;
    private @Nullable List<GetFleetJavaMigrationAnalysisResultsFilter> filters;
    /**
     * @return The fleet OCID.
     * 
     */
    private String fleetId;
    /**
     * @return The hostname of the managed instance that hosts the application for which the Java migration analysis was performed.
     * 
     */
    private @Nullable String hostName;
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
    /**
     * @return The name of the application for which the Java migration analysis was performed.
     * 
     */
    public Optional<String> applicationName() {
        return Optional.ofNullable(this.applicationName);
    }
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
     * @return The hostname of the managed instance that hosts the application for which the Java migration analysis was performed.
     * 
     */
    public Optional<String> hostName() {
        return Optional.ofNullable(this.hostName);
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
        private @Nullable String applicationName;
        private @Nullable List<GetFleetJavaMigrationAnalysisResultsFilter> filters;
        private String fleetId;
        private @Nullable String hostName;
        private String id;
        private List<GetFleetJavaMigrationAnalysisResultsJavaMigrationAnalysisResultCollection> javaMigrationAnalysisResultCollections;
        private @Nullable String managedInstanceId;
        private @Nullable String timeEnd;
        private @Nullable String timeStart;
        public Builder() {}
        public Builder(GetFleetJavaMigrationAnalysisResultsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.applicationName = defaults.applicationName;
    	      this.filters = defaults.filters;
    	      this.fleetId = defaults.fleetId;
    	      this.hostName = defaults.hostName;
    	      this.id = defaults.id;
    	      this.javaMigrationAnalysisResultCollections = defaults.javaMigrationAnalysisResultCollections;
    	      this.managedInstanceId = defaults.managedInstanceId;
    	      this.timeEnd = defaults.timeEnd;
    	      this.timeStart = defaults.timeStart;
        }

        @CustomType.Setter
        public Builder applicationName(@Nullable String applicationName) {

            this.applicationName = applicationName;
            return this;
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
            if (fleetId == null) {
              throw new MissingRequiredPropertyException("GetFleetJavaMigrationAnalysisResultsResult", "fleetId");
            }
            this.fleetId = fleetId;
            return this;
        }
        @CustomType.Setter
        public Builder hostName(@Nullable String hostName) {

            this.hostName = hostName;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetFleetJavaMigrationAnalysisResultsResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder javaMigrationAnalysisResultCollections(List<GetFleetJavaMigrationAnalysisResultsJavaMigrationAnalysisResultCollection> javaMigrationAnalysisResultCollections) {
            if (javaMigrationAnalysisResultCollections == null) {
              throw new MissingRequiredPropertyException("GetFleetJavaMigrationAnalysisResultsResult", "javaMigrationAnalysisResultCollections");
            }
            this.javaMigrationAnalysisResultCollections = javaMigrationAnalysisResultCollections;
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
            final var _resultValue = new GetFleetJavaMigrationAnalysisResultsResult();
            _resultValue.applicationName = applicationName;
            _resultValue.filters = filters;
            _resultValue.fleetId = fleetId;
            _resultValue.hostName = hostName;
            _resultValue.id = id;
            _resultValue.javaMigrationAnalysisResultCollections = javaMigrationAnalysisResultCollections;
            _resultValue.managedInstanceId = managedInstanceId;
            _resultValue.timeEnd = timeEnd;
            _resultValue.timeStart = timeStart;
            return _resultValue;
        }
    }
}
