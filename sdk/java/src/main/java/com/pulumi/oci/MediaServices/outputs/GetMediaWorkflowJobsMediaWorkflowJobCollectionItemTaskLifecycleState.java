// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.MediaServices.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetMediaWorkflowJobsMediaWorkflowJobCollectionItemTaskLifecycleState {
    /**
     * @return Unique key within a MediaWorkflowJob for the task.
     * 
     */
    private String key;
    /**
     * @return The lifecycle details of MediaWorkflowJob task.
     * 
     */
    private String lifecycleDetails;
    /**
     * @return A filter to return only the resources with lifecycleState matching the given lifecycleState.
     * 
     */
    private String state;

    private GetMediaWorkflowJobsMediaWorkflowJobCollectionItemTaskLifecycleState() {}
    /**
     * @return Unique key within a MediaWorkflowJob for the task.
     * 
     */
    public String key() {
        return this.key;
    }
    /**
     * @return The lifecycle details of MediaWorkflowJob task.
     * 
     */
    public String lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * @return A filter to return only the resources with lifecycleState matching the given lifecycleState.
     * 
     */
    public String state() {
        return this.state;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetMediaWorkflowJobsMediaWorkflowJobCollectionItemTaskLifecycleState defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String key;
        private String lifecycleDetails;
        private String state;
        public Builder() {}
        public Builder(GetMediaWorkflowJobsMediaWorkflowJobCollectionItemTaskLifecycleState defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.key = defaults.key;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.state = defaults.state;
        }

        @CustomType.Setter
        public Builder key(String key) {
            if (key == null) {
              throw new MissingRequiredPropertyException("GetMediaWorkflowJobsMediaWorkflowJobCollectionItemTaskLifecycleState", "key");
            }
            this.key = key;
            return this;
        }
        @CustomType.Setter
        public Builder lifecycleDetails(String lifecycleDetails) {
            if (lifecycleDetails == null) {
              throw new MissingRequiredPropertyException("GetMediaWorkflowJobsMediaWorkflowJobCollectionItemTaskLifecycleState", "lifecycleDetails");
            }
            this.lifecycleDetails = lifecycleDetails;
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetMediaWorkflowJobsMediaWorkflowJobCollectionItemTaskLifecycleState", "state");
            }
            this.state = state;
            return this;
        }
        public GetMediaWorkflowJobsMediaWorkflowJobCollectionItemTaskLifecycleState build() {
            final var _resultValue = new GetMediaWorkflowJobsMediaWorkflowJobCollectionItemTaskLifecycleState();
            _resultValue.key = key;
            _resultValue.lifecycleDetails = lifecycleDetails;
            _resultValue.state = state;
            return _resultValue;
        }
    }
}
