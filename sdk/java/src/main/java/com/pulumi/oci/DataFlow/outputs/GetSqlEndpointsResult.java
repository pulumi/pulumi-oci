// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataFlow.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DataFlow.outputs.GetSqlEndpointsFilter;
import com.pulumi.oci.DataFlow.outputs.GetSqlEndpointsSqlEndpointCollection;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetSqlEndpointsResult {
    /**
     * @return The OCID of a compartment.
     * 
     */
    private @Nullable String compartmentId;
    /**
     * @return The SQL Endpoint name, which can be changed.
     * 
     */
    private @Nullable String displayName;
    private @Nullable List<GetSqlEndpointsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The list of sql_endpoint_collection.
     * 
     */
    private List<GetSqlEndpointsSqlEndpointCollection> sqlEndpointCollections;
    private @Nullable String sqlEndpointId;
    /**
     * @return The current state of the Sql Endpoint.
     * 
     */
    private @Nullable String state;

    private GetSqlEndpointsResult() {}
    /**
     * @return The OCID of a compartment.
     * 
     */
    public Optional<String> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }
    /**
     * @return The SQL Endpoint name, which can be changed.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public List<GetSqlEndpointsFilter> filters() {
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
     * @return The list of sql_endpoint_collection.
     * 
     */
    public List<GetSqlEndpointsSqlEndpointCollection> sqlEndpointCollections() {
        return this.sqlEndpointCollections;
    }
    public Optional<String> sqlEndpointId() {
        return Optional.ofNullable(this.sqlEndpointId);
    }
    /**
     * @return The current state of the Sql Endpoint.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetSqlEndpointsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String compartmentId;
        private @Nullable String displayName;
        private @Nullable List<GetSqlEndpointsFilter> filters;
        private String id;
        private List<GetSqlEndpointsSqlEndpointCollection> sqlEndpointCollections;
        private @Nullable String sqlEndpointId;
        private @Nullable String state;
        public Builder() {}
        public Builder(GetSqlEndpointsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.displayName = defaults.displayName;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.sqlEndpointCollections = defaults.sqlEndpointCollections;
    	      this.sqlEndpointId = defaults.sqlEndpointId;
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
        public Builder filters(@Nullable List<GetSqlEndpointsFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetSqlEndpointsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetSqlEndpointsResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder sqlEndpointCollections(List<GetSqlEndpointsSqlEndpointCollection> sqlEndpointCollections) {
            if (sqlEndpointCollections == null) {
              throw new MissingRequiredPropertyException("GetSqlEndpointsResult", "sqlEndpointCollections");
            }
            this.sqlEndpointCollections = sqlEndpointCollections;
            return this;
        }
        public Builder sqlEndpointCollections(GetSqlEndpointsSqlEndpointCollection... sqlEndpointCollections) {
            return sqlEndpointCollections(List.of(sqlEndpointCollections));
        }
        @CustomType.Setter
        public Builder sqlEndpointId(@Nullable String sqlEndpointId) {

            this.sqlEndpointId = sqlEndpointId;
            return this;
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {

            this.state = state;
            return this;
        }
        public GetSqlEndpointsResult build() {
            final var _resultValue = new GetSqlEndpointsResult();
            _resultValue.compartmentId = compartmentId;
            _resultValue.displayName = displayName;
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.sqlEndpointCollections = sqlEndpointCollections;
            _resultValue.sqlEndpointId = sqlEndpointId;
            _resultValue.state = state;
            return _resultValue;
        }
    }
}
