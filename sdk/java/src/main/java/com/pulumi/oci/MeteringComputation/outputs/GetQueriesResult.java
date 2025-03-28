// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.MeteringComputation.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.MeteringComputation.outputs.GetQueriesFilter;
import com.pulumi.oci.MeteringComputation.outputs.GetQueriesQueryCollection;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nullable;

@CustomType
public final class GetQueriesResult {
    /**
     * @return The compartment OCID.
     * 
     */
    private String compartmentId;
    /**
     * @return The filter object for query usage.
     * 
     */
    private @Nullable List<GetQueriesFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The list of query_collection.
     * 
     */
    private List<GetQueriesQueryCollection> queryCollections;

    private GetQueriesResult() {}
    /**
     * @return The compartment OCID.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The filter object for query usage.
     * 
     */
    public List<GetQueriesFilter> filters() {
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
     * @return The list of query_collection.
     * 
     */
    public List<GetQueriesQueryCollection> queryCollections() {
        return this.queryCollections;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetQueriesResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private @Nullable List<GetQueriesFilter> filters;
        private String id;
        private List<GetQueriesQueryCollection> queryCollections;
        public Builder() {}
        public Builder(GetQueriesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.queryCollections = defaults.queryCollections;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetQueriesResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetQueriesFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetQueriesFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetQueriesResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder queryCollections(List<GetQueriesQueryCollection> queryCollections) {
            if (queryCollections == null) {
              throw new MissingRequiredPropertyException("GetQueriesResult", "queryCollections");
            }
            this.queryCollections = queryCollections;
            return this;
        }
        public Builder queryCollections(GetQueriesQueryCollection... queryCollections) {
            return queryCollections(List.of(queryCollections));
        }
        public GetQueriesResult build() {
            final var _resultValue = new GetQueriesResult();
            _resultValue.compartmentId = compartmentId;
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.queryCollections = queryCollections;
            return _resultValue;
        }
    }
}
