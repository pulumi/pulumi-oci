// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ContainerEngine.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.ContainerEngine.outputs.GetWorkRequestsWorkRequestResource;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetWorkRequestsWorkRequest {
    /**
     * @return The OCID of the compartment.
     * 
     */
    private final String compartmentId;
    /**
     * @return The OCID of the work request.
     * 
     */
    private final String id;
    /**
     * @return The type of work the work request is doing.
     * 
     */
    private final String operationType;
    /**
     * @return The resources this work request affects.
     * 
     */
    private final List<GetWorkRequestsWorkRequestResource> resources;
    /**
     * @return A work request status to filter on. Can have multiple parameters of this name.
     * 
     */
    private final String status;
    /**
     * @return The time the work request was accepted.
     * 
     */
    private final String timeAccepted;
    /**
     * @return The time the work request was finished.
     * 
     */
    private final String timeFinished;
    /**
     * @return The time the work request was started.
     * 
     */
    private final String timeStarted;

    @CustomType.Constructor
    private GetWorkRequestsWorkRequest(
        @CustomType.Parameter("compartmentId") String compartmentId,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("operationType") String operationType,
        @CustomType.Parameter("resources") List<GetWorkRequestsWorkRequestResource> resources,
        @CustomType.Parameter("status") String status,
        @CustomType.Parameter("timeAccepted") String timeAccepted,
        @CustomType.Parameter("timeFinished") String timeFinished,
        @CustomType.Parameter("timeStarted") String timeStarted) {
        this.compartmentId = compartmentId;
        this.id = id;
        this.operationType = operationType;
        this.resources = resources;
        this.status = status;
        this.timeAccepted = timeAccepted;
        this.timeFinished = timeFinished;
        this.timeStarted = timeStarted;
    }

    /**
     * @return The OCID of the compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The OCID of the work request.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The type of work the work request is doing.
     * 
     */
    public String operationType() {
        return this.operationType;
    }
    /**
     * @return The resources this work request affects.
     * 
     */
    public List<GetWorkRequestsWorkRequestResource> resources() {
        return this.resources;
    }
    /**
     * @return A work request status to filter on. Can have multiple parameters of this name.
     * 
     */
    public String status() {
        return this.status;
    }
    /**
     * @return The time the work request was accepted.
     * 
     */
    public String timeAccepted() {
        return this.timeAccepted;
    }
    /**
     * @return The time the work request was finished.
     * 
     */
    public String timeFinished() {
        return this.timeFinished;
    }
    /**
     * @return The time the work request was started.
     * 
     */
    public String timeStarted() {
        return this.timeStarted;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetWorkRequestsWorkRequest defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String compartmentId;
        private String id;
        private String operationType;
        private List<GetWorkRequestsWorkRequestResource> resources;
        private String status;
        private String timeAccepted;
        private String timeFinished;
        private String timeStarted;

        public Builder() {
    	      // Empty
        }

        public Builder(GetWorkRequestsWorkRequest defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.id = defaults.id;
    	      this.operationType = defaults.operationType;
    	      this.resources = defaults.resources;
    	      this.status = defaults.status;
    	      this.timeAccepted = defaults.timeAccepted;
    	      this.timeFinished = defaults.timeFinished;
    	      this.timeStarted = defaults.timeStarted;
        }

        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder operationType(String operationType) {
            this.operationType = Objects.requireNonNull(operationType);
            return this;
        }
        public Builder resources(List<GetWorkRequestsWorkRequestResource> resources) {
            this.resources = Objects.requireNonNull(resources);
            return this;
        }
        public Builder resources(GetWorkRequestsWorkRequestResource... resources) {
            return resources(List.of(resources));
        }
        public Builder status(String status) {
            this.status = Objects.requireNonNull(status);
            return this;
        }
        public Builder timeAccepted(String timeAccepted) {
            this.timeAccepted = Objects.requireNonNull(timeAccepted);
            return this;
        }
        public Builder timeFinished(String timeFinished) {
            this.timeFinished = Objects.requireNonNull(timeFinished);
            return this;
        }
        public Builder timeStarted(String timeStarted) {
            this.timeStarted = Objects.requireNonNull(timeStarted);
            return this;
        }        public GetWorkRequestsWorkRequest build() {
            return new GetWorkRequestsWorkRequest(compartmentId, id, operationType, resources, status, timeAccepted, timeFinished, timeStarted);
        }
    }
}
