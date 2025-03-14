// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.AiLanguage.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.AiLanguage.outputs.GetEndpointsEndpointCollection;
import com.pulumi.oci.AiLanguage.outputs.GetEndpointsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetEndpointsResult {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the endpoint compartment.
     * 
     */
    private String compartmentId;
    /**
     * @return A user-friendly display name for the resource. It should be unique and can be modified. Avoid entering confidential information.
     * 
     */
    private @Nullable String displayName;
    /**
     * @return The list of endpoint_collection.
     * 
     */
    private List<GetEndpointsEndpointCollection> endpointCollections;
    private @Nullable List<GetEndpointsFilter> filters;
    /**
     * @return Unique identifier endpoint OCID of an endpoint that is immutable on creation.
     * 
     */
    private @Nullable String id;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the model to associate with the endpoint.
     * 
     */
    private @Nullable String modelId;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate with the Endpoint.
     * 
     */
    private @Nullable String projectId;
    /**
     * @return The state of the endpoint.
     * 
     */
    private @Nullable String state;

    private GetEndpointsResult() {}
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the endpoint compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return A user-friendly display name for the resource. It should be unique and can be modified. Avoid entering confidential information.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    /**
     * @return The list of endpoint_collection.
     * 
     */
    public List<GetEndpointsEndpointCollection> endpointCollections() {
        return this.endpointCollections;
    }
    public List<GetEndpointsFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return Unique identifier endpoint OCID of an endpoint that is immutable on creation.
     * 
     */
    public Optional<String> id() {
        return Optional.ofNullable(this.id);
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the model to associate with the endpoint.
     * 
     */
    public Optional<String> modelId() {
        return Optional.ofNullable(this.modelId);
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate with the Endpoint.
     * 
     */
    public Optional<String> projectId() {
        return Optional.ofNullable(this.projectId);
    }
    /**
     * @return The state of the endpoint.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetEndpointsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private @Nullable String displayName;
        private List<GetEndpointsEndpointCollection> endpointCollections;
        private @Nullable List<GetEndpointsFilter> filters;
        private @Nullable String id;
        private @Nullable String modelId;
        private @Nullable String projectId;
        private @Nullable String state;
        public Builder() {}
        public Builder(GetEndpointsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.displayName = defaults.displayName;
    	      this.endpointCollections = defaults.endpointCollections;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.modelId = defaults.modelId;
    	      this.projectId = defaults.projectId;
    	      this.state = defaults.state;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetEndpointsResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(@Nullable String displayName) {

            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder endpointCollections(List<GetEndpointsEndpointCollection> endpointCollections) {
            if (endpointCollections == null) {
              throw new MissingRequiredPropertyException("GetEndpointsResult", "endpointCollections");
            }
            this.endpointCollections = endpointCollections;
            return this;
        }
        public Builder endpointCollections(GetEndpointsEndpointCollection... endpointCollections) {
            return endpointCollections(List.of(endpointCollections));
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetEndpointsFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetEndpointsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(@Nullable String id) {

            this.id = id;
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
        public GetEndpointsResult build() {
            final var _resultValue = new GetEndpointsResult();
            _resultValue.compartmentId = compartmentId;
            _resultValue.displayName = displayName;
            _resultValue.endpointCollections = endpointCollections;
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.modelId = modelId;
            _resultValue.projectId = projectId;
            _resultValue.state = state;
            return _resultValue;
        }
    }
}
