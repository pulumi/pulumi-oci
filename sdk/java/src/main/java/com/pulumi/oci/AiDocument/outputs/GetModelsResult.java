// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.AiDocument.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.AiDocument.outputs.GetModelsFilter;
import com.pulumi.oci.AiDocument.outputs.GetModelsModelCollection;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetModelsResult {
    /**
     * @return The compartment identifier.
     * 
     */
    private @Nullable String compartmentId;
    /**
     * @return A human-friendly name for the model, which can be changed.
     * 
     */
    private @Nullable String displayName;
    private @Nullable List<GetModelsFilter> filters;
    /**
     * @return A unique identifier that is immutable after creation.
     * 
     */
    private @Nullable String id;
    /**
     * @return The list of model_collection.
     * 
     */
    private List<GetModelsModelCollection> modelCollections;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project that contains the model.
     * 
     */
    private @Nullable String projectId;
    /**
     * @return The current state of the model.
     * 
     */
    private @Nullable String state;

    private GetModelsResult() {}
    /**
     * @return The compartment identifier.
     * 
     */
    public Optional<String> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }
    /**
     * @return A human-friendly name for the model, which can be changed.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public List<GetModelsFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return A unique identifier that is immutable after creation.
     * 
     */
    public Optional<String> id() {
        return Optional.ofNullable(this.id);
    }
    /**
     * @return The list of model_collection.
     * 
     */
    public List<GetModelsModelCollection> modelCollections() {
        return this.modelCollections;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project that contains the model.
     * 
     */
    public Optional<String> projectId() {
        return Optional.ofNullable(this.projectId);
    }
    /**
     * @return The current state of the model.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetModelsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String compartmentId;
        private @Nullable String displayName;
        private @Nullable List<GetModelsFilter> filters;
        private @Nullable String id;
        private List<GetModelsModelCollection> modelCollections;
        private @Nullable String projectId;
        private @Nullable String state;
        public Builder() {}
        public Builder(GetModelsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.displayName = defaults.displayName;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.modelCollections = defaults.modelCollections;
    	      this.projectId = defaults.projectId;
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
        public Builder filters(@Nullable List<GetModelsFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetModelsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(@Nullable String id) {

            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder modelCollections(List<GetModelsModelCollection> modelCollections) {
            if (modelCollections == null) {
              throw new MissingRequiredPropertyException("GetModelsResult", "modelCollections");
            }
            this.modelCollections = modelCollections;
            return this;
        }
        public Builder modelCollections(GetModelsModelCollection... modelCollections) {
            return modelCollections(List.of(modelCollections));
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
        public GetModelsResult build() {
            final var _resultValue = new GetModelsResult();
            _resultValue.compartmentId = compartmentId;
            _resultValue.displayName = displayName;
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.modelCollections = modelCollections;
            _resultValue.projectId = projectId;
            _resultValue.state = state;
            return _resultValue;
        }
    }
}
