// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.NetworkLoadBalancer.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.NetworkLoadBalancer.outputs.GetBackendSetsBackendSetCollection;
import com.pulumi.oci.NetworkLoadBalancer.outputs.GetBackendSetsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nullable;

@CustomType
public final class GetBackendSetsResult {
    /**
     * @return The list of backend_set_collection.
     * 
     */
    private List<GetBackendSetsBackendSetCollection> backendSetCollections;
    private @Nullable List<GetBackendSetsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    private String networkLoadBalancerId;

    private GetBackendSetsResult() {}
    /**
     * @return The list of backend_set_collection.
     * 
     */
    public List<GetBackendSetsBackendSetCollection> backendSetCollections() {
        return this.backendSetCollections;
    }
    public List<GetBackendSetsFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    public String networkLoadBalancerId() {
        return this.networkLoadBalancerId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetBackendSetsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetBackendSetsBackendSetCollection> backendSetCollections;
        private @Nullable List<GetBackendSetsFilter> filters;
        private String id;
        private String networkLoadBalancerId;
        public Builder() {}
        public Builder(GetBackendSetsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.backendSetCollections = defaults.backendSetCollections;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.networkLoadBalancerId = defaults.networkLoadBalancerId;
        }

        @CustomType.Setter
        public Builder backendSetCollections(List<GetBackendSetsBackendSetCollection> backendSetCollections) {
            if (backendSetCollections == null) {
              throw new MissingRequiredPropertyException("GetBackendSetsResult", "backendSetCollections");
            }
            this.backendSetCollections = backendSetCollections;
            return this;
        }
        public Builder backendSetCollections(GetBackendSetsBackendSetCollection... backendSetCollections) {
            return backendSetCollections(List.of(backendSetCollections));
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetBackendSetsFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetBackendSetsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetBackendSetsResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder networkLoadBalancerId(String networkLoadBalancerId) {
            if (networkLoadBalancerId == null) {
              throw new MissingRequiredPropertyException("GetBackendSetsResult", "networkLoadBalancerId");
            }
            this.networkLoadBalancerId = networkLoadBalancerId;
            return this;
        }
        public GetBackendSetsResult build() {
            final var _resultValue = new GetBackendSetsResult();
            _resultValue.backendSetCollections = backendSetCollections;
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.networkLoadBalancerId = networkLoadBalancerId;
            return _resultValue;
        }
    }
}
