// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.AiAnomalyDetection.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.AiAnomalyDetection.outputs.GetDetectAnomalyJobsDetectAnomalyJobCollection;
import com.pulumi.oci.AiAnomalyDetection.outputs.GetDetectAnomalyJobsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetDetectAnomalyJobsResult {
    /**
     * @return The OCID of the compartment that starts the job.
     * 
     */
    private String compartmentId;
    /**
     * @return The list of detect_anomaly_job_collection.
     * 
     */
    private List<GetDetectAnomalyJobsDetectAnomalyJobCollection> detectAnomalyJobCollections;
    private @Nullable String detectAnomalyJobId;
    /**
     * @return Detect anomaly job display name.
     * 
     */
    private @Nullable String displayName;
    private @Nullable List<GetDetectAnomalyJobsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The OCID of the trained model.
     * 
     */
    private @Nullable String modelId;
    /**
     * @return The OCID of the project.
     * 
     */
    private @Nullable String projectId;
    /**
     * @return The current state of the batch document job.
     * 
     */
    private @Nullable String state;

    private GetDetectAnomalyJobsResult() {}
    /**
     * @return The OCID of the compartment that starts the job.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The list of detect_anomaly_job_collection.
     * 
     */
    public List<GetDetectAnomalyJobsDetectAnomalyJobCollection> detectAnomalyJobCollections() {
        return this.detectAnomalyJobCollections;
    }
    public Optional<String> detectAnomalyJobId() {
        return Optional.ofNullable(this.detectAnomalyJobId);
    }
    /**
     * @return Detect anomaly job display name.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public List<GetDetectAnomalyJobsFilter> filters() {
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
     * @return The OCID of the trained model.
     * 
     */
    public Optional<String> modelId() {
        return Optional.ofNullable(this.modelId);
    }
    /**
     * @return The OCID of the project.
     * 
     */
    public Optional<String> projectId() {
        return Optional.ofNullable(this.projectId);
    }
    /**
     * @return The current state of the batch document job.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDetectAnomalyJobsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private List<GetDetectAnomalyJobsDetectAnomalyJobCollection> detectAnomalyJobCollections;
        private @Nullable String detectAnomalyJobId;
        private @Nullable String displayName;
        private @Nullable List<GetDetectAnomalyJobsFilter> filters;
        private String id;
        private @Nullable String modelId;
        private @Nullable String projectId;
        private @Nullable String state;
        public Builder() {}
        public Builder(GetDetectAnomalyJobsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.detectAnomalyJobCollections = defaults.detectAnomalyJobCollections;
    	      this.detectAnomalyJobId = defaults.detectAnomalyJobId;
    	      this.displayName = defaults.displayName;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.modelId = defaults.modelId;
    	      this.projectId = defaults.projectId;
    	      this.state = defaults.state;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder detectAnomalyJobCollections(List<GetDetectAnomalyJobsDetectAnomalyJobCollection> detectAnomalyJobCollections) {
            this.detectAnomalyJobCollections = Objects.requireNonNull(detectAnomalyJobCollections);
            return this;
        }
        public Builder detectAnomalyJobCollections(GetDetectAnomalyJobsDetectAnomalyJobCollection... detectAnomalyJobCollections) {
            return detectAnomalyJobCollections(List.of(detectAnomalyJobCollections));
        }
        @CustomType.Setter
        public Builder detectAnomalyJobId(@Nullable String detectAnomalyJobId) {
            this.detectAnomalyJobId = detectAnomalyJobId;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(@Nullable String displayName) {
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetDetectAnomalyJobsFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetDetectAnomalyJobsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder modelId(@Nullable String modelId) {
            this.modelId = modelId;
            return this;
        }
        @CustomType.Setter
        public Builder projectId(@Nullable String projectId) {
            this.projectId = projectId;
            return this;
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {
            this.state = state;
            return this;
        }
        public GetDetectAnomalyJobsResult build() {
            final var o = new GetDetectAnomalyJobsResult();
            o.compartmentId = compartmentId;
            o.detectAnomalyJobCollections = detectAnomalyJobCollections;
            o.detectAnomalyJobId = detectAnomalyJobId;
            o.displayName = displayName;
            o.filters = filters;
            o.id = id;
            o.modelId = modelId;
            o.projectId = projectId;
            o.state = state;
            return o;
        }
    }
}