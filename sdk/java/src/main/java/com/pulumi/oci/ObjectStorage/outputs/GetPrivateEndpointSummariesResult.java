// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ObjectStorage.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.ObjectStorage.outputs.GetPrivateEndpointSummariesFilter;
import com.pulumi.oci.ObjectStorage.outputs.GetPrivateEndpointSummariesPrivateEndpointSummary;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nullable;

@CustomType
public final class GetPrivateEndpointSummariesResult {
    private String compartmentId;
    private @Nullable List<GetPrivateEndpointSummariesFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    private String namespace;
    private List<GetPrivateEndpointSummariesPrivateEndpointSummary> privateEndpointSummaries;

    private GetPrivateEndpointSummariesResult() {}
    public String compartmentId() {
        return this.compartmentId;
    }
    public List<GetPrivateEndpointSummariesFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    public String namespace() {
        return this.namespace;
    }
    public List<GetPrivateEndpointSummariesPrivateEndpointSummary> privateEndpointSummaries() {
        return this.privateEndpointSummaries;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetPrivateEndpointSummariesResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private @Nullable List<GetPrivateEndpointSummariesFilter> filters;
        private String id;
        private String namespace;
        private List<GetPrivateEndpointSummariesPrivateEndpointSummary> privateEndpointSummaries;
        public Builder() {}
        public Builder(GetPrivateEndpointSummariesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.namespace = defaults.namespace;
    	      this.privateEndpointSummaries = defaults.privateEndpointSummaries;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetPrivateEndpointSummariesResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetPrivateEndpointSummariesFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetPrivateEndpointSummariesFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetPrivateEndpointSummariesResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder namespace(String namespace) {
            if (namespace == null) {
              throw new MissingRequiredPropertyException("GetPrivateEndpointSummariesResult", "namespace");
            }
            this.namespace = namespace;
            return this;
        }
        @CustomType.Setter
        public Builder privateEndpointSummaries(List<GetPrivateEndpointSummariesPrivateEndpointSummary> privateEndpointSummaries) {
            if (privateEndpointSummaries == null) {
              throw new MissingRequiredPropertyException("GetPrivateEndpointSummariesResult", "privateEndpointSummaries");
            }
            this.privateEndpointSummaries = privateEndpointSummaries;
            return this;
        }
        public Builder privateEndpointSummaries(GetPrivateEndpointSummariesPrivateEndpointSummary... privateEndpointSummaries) {
            return privateEndpointSummaries(List.of(privateEndpointSummaries));
        }
        public GetPrivateEndpointSummariesResult build() {
            final var _resultValue = new GetPrivateEndpointSummariesResult();
            _resultValue.compartmentId = compartmentId;
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.namespace = namespace;
            _resultValue.privateEndpointSummaries = privateEndpointSummaries;
            return _resultValue;
        }
    }
}
