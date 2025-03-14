// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DataSafe.outputs.GetMaskingPolicyMaskingSchemasFilter;
import com.pulumi.oci.DataSafe.outputs.GetMaskingPolicyMaskingSchemasMaskingSchemaCollection;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nullable;

@CustomType
public final class GetMaskingPolicyMaskingSchemasResult {
    private @Nullable List<GetMaskingPolicyMaskingSchemasFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    private String maskingPolicyId;
    /**
     * @return The list of masking_schema_collection.
     * 
     */
    private List<GetMaskingPolicyMaskingSchemasMaskingSchemaCollection> maskingSchemaCollections;
    /**
     * @return The database schema that contains the masking column.
     * 
     */
    private @Nullable List<String> schemaNames;

    private GetMaskingPolicyMaskingSchemasResult() {}
    public List<GetMaskingPolicyMaskingSchemasFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    public String maskingPolicyId() {
        return this.maskingPolicyId;
    }
    /**
     * @return The list of masking_schema_collection.
     * 
     */
    public List<GetMaskingPolicyMaskingSchemasMaskingSchemaCollection> maskingSchemaCollections() {
        return this.maskingSchemaCollections;
    }
    /**
     * @return The database schema that contains the masking column.
     * 
     */
    public List<String> schemaNames() {
        return this.schemaNames == null ? List.of() : this.schemaNames;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetMaskingPolicyMaskingSchemasResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable List<GetMaskingPolicyMaskingSchemasFilter> filters;
        private String id;
        private String maskingPolicyId;
        private List<GetMaskingPolicyMaskingSchemasMaskingSchemaCollection> maskingSchemaCollections;
        private @Nullable List<String> schemaNames;
        public Builder() {}
        public Builder(GetMaskingPolicyMaskingSchemasResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.maskingPolicyId = defaults.maskingPolicyId;
    	      this.maskingSchemaCollections = defaults.maskingSchemaCollections;
    	      this.schemaNames = defaults.schemaNames;
        }

        @CustomType.Setter
        public Builder filters(@Nullable List<GetMaskingPolicyMaskingSchemasFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetMaskingPolicyMaskingSchemasFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetMaskingPolicyMaskingSchemasResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder maskingPolicyId(String maskingPolicyId) {
            if (maskingPolicyId == null) {
              throw new MissingRequiredPropertyException("GetMaskingPolicyMaskingSchemasResult", "maskingPolicyId");
            }
            this.maskingPolicyId = maskingPolicyId;
            return this;
        }
        @CustomType.Setter
        public Builder maskingSchemaCollections(List<GetMaskingPolicyMaskingSchemasMaskingSchemaCollection> maskingSchemaCollections) {
            if (maskingSchemaCollections == null) {
              throw new MissingRequiredPropertyException("GetMaskingPolicyMaskingSchemasResult", "maskingSchemaCollections");
            }
            this.maskingSchemaCollections = maskingSchemaCollections;
            return this;
        }
        public Builder maskingSchemaCollections(GetMaskingPolicyMaskingSchemasMaskingSchemaCollection... maskingSchemaCollections) {
            return maskingSchemaCollections(List.of(maskingSchemaCollections));
        }
        @CustomType.Setter
        public Builder schemaNames(@Nullable List<String> schemaNames) {

            this.schemaNames = schemaNames;
            return this;
        }
        public Builder schemaNames(String... schemaNames) {
            return schemaNames(List.of(schemaNames));
        }
        public GetMaskingPolicyMaskingSchemasResult build() {
            final var _resultValue = new GetMaskingPolicyMaskingSchemasResult();
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.maskingPolicyId = maskingPolicyId;
            _resultValue.maskingSchemaCollections = maskingSchemaCollections;
            _resultValue.schemaNames = schemaNames;
            return _resultValue;
        }
    }
}
