// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.MeteringComputation.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.MeteringComputation.outputs.GetUsageCarbonEmissionsQueryQueryDefinition;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetUsageCarbonEmissionsQueryResult {
    /**
     * @return The compartment OCID.
     * 
     */
    private String compartmentId;
    /**
     * @return The query OCID.
     * 
     */
    private String id;
    /**
     * @return The common fields for queries.
     * 
     */
    private List<GetUsageCarbonEmissionsQueryQueryDefinition> queryDefinitions;
    private String usageCarbonEmissionsQueryId;

    private GetUsageCarbonEmissionsQueryResult() {}
    /**
     * @return The compartment OCID.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The query OCID.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The common fields for queries.
     * 
     */
    public List<GetUsageCarbonEmissionsQueryQueryDefinition> queryDefinitions() {
        return this.queryDefinitions;
    }
    public String usageCarbonEmissionsQueryId() {
        return this.usageCarbonEmissionsQueryId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetUsageCarbonEmissionsQueryResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private String id;
        private List<GetUsageCarbonEmissionsQueryQueryDefinition> queryDefinitions;
        private String usageCarbonEmissionsQueryId;
        public Builder() {}
        public Builder(GetUsageCarbonEmissionsQueryResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.id = defaults.id;
    	      this.queryDefinitions = defaults.queryDefinitions;
    	      this.usageCarbonEmissionsQueryId = defaults.usageCarbonEmissionsQueryId;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetUsageCarbonEmissionsQueryResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetUsageCarbonEmissionsQueryResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder queryDefinitions(List<GetUsageCarbonEmissionsQueryQueryDefinition> queryDefinitions) {
            if (queryDefinitions == null) {
              throw new MissingRequiredPropertyException("GetUsageCarbonEmissionsQueryResult", "queryDefinitions");
            }
            this.queryDefinitions = queryDefinitions;
            return this;
        }
        public Builder queryDefinitions(GetUsageCarbonEmissionsQueryQueryDefinition... queryDefinitions) {
            return queryDefinitions(List.of(queryDefinitions));
        }
        @CustomType.Setter
        public Builder usageCarbonEmissionsQueryId(String usageCarbonEmissionsQueryId) {
            if (usageCarbonEmissionsQueryId == null) {
              throw new MissingRequiredPropertyException("GetUsageCarbonEmissionsQueryResult", "usageCarbonEmissionsQueryId");
            }
            this.usageCarbonEmissionsQueryId = usageCarbonEmissionsQueryId;
            return this;
        }
        public GetUsageCarbonEmissionsQueryResult build() {
            final var _resultValue = new GetUsageCarbonEmissionsQueryResult();
            _resultValue.compartmentId = compartmentId;
            _resultValue.id = id;
            _resultValue.queryDefinitions = queryDefinitions;
            _resultValue.usageCarbonEmissionsQueryId = usageCarbonEmissionsQueryId;
            return _resultValue;
        }
    }
}
