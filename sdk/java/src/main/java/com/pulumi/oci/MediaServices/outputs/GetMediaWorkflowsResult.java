// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.MediaServices.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.MediaServices.outputs.GetMediaWorkflowsFilter;
import com.pulumi.oci.MediaServices.outputs.GetMediaWorkflowsMediaWorkflowCollection;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetMediaWorkflowsResult {
    /**
     * @return The compartment ID of the lock.
     * 
     */
    private @Nullable String compartmentId;
    /**
     * @return Name of the Media Workflow. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    private @Nullable String displayName;
    private @Nullable List<GetMediaWorkflowsFilter> filters;
    /**
     * @return Unique identifier that is immutable on creation.
     * 
     */
    private @Nullable String id;
    /**
     * @return The list of media_workflow_collection.
     * 
     */
    private List<GetMediaWorkflowsMediaWorkflowCollection> mediaWorkflowCollections;
    /**
     * @return The current state of the MediaWorkflow.
     * 
     */
    private @Nullable String state;

    private GetMediaWorkflowsResult() {}
    /**
     * @return The compartment ID of the lock.
     * 
     */
    public Optional<String> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }
    /**
     * @return Name of the Media Workflow. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public List<GetMediaWorkflowsFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return Unique identifier that is immutable on creation.
     * 
     */
    public Optional<String> id() {
        return Optional.ofNullable(this.id);
    }
    /**
     * @return The list of media_workflow_collection.
     * 
     */
    public List<GetMediaWorkflowsMediaWorkflowCollection> mediaWorkflowCollections() {
        return this.mediaWorkflowCollections;
    }
    /**
     * @return The current state of the MediaWorkflow.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetMediaWorkflowsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String compartmentId;
        private @Nullable String displayName;
        private @Nullable List<GetMediaWorkflowsFilter> filters;
        private @Nullable String id;
        private List<GetMediaWorkflowsMediaWorkflowCollection> mediaWorkflowCollections;
        private @Nullable String state;
        public Builder() {}
        public Builder(GetMediaWorkflowsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.displayName = defaults.displayName;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.mediaWorkflowCollections = defaults.mediaWorkflowCollections;
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
        public Builder filters(@Nullable List<GetMediaWorkflowsFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetMediaWorkflowsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(@Nullable String id) {

            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder mediaWorkflowCollections(List<GetMediaWorkflowsMediaWorkflowCollection> mediaWorkflowCollections) {
            if (mediaWorkflowCollections == null) {
              throw new MissingRequiredPropertyException("GetMediaWorkflowsResult", "mediaWorkflowCollections");
            }
            this.mediaWorkflowCollections = mediaWorkflowCollections;
            return this;
        }
        public Builder mediaWorkflowCollections(GetMediaWorkflowsMediaWorkflowCollection... mediaWorkflowCollections) {
            return mediaWorkflowCollections(List.of(mediaWorkflowCollections));
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {

            this.state = state;
            return this;
        }
        public GetMediaWorkflowsResult build() {
            final var _resultValue = new GetMediaWorkflowsResult();
            _resultValue.compartmentId = compartmentId;
            _resultValue.displayName = displayName;
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.mediaWorkflowCollections = mediaWorkflowCollections;
            _resultValue.state = state;
            return _resultValue;
        }
    }
}
