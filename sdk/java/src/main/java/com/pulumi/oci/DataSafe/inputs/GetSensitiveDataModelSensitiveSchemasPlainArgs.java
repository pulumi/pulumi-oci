// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DataSafe.inputs.GetSensitiveDataModelSensitiveSchemasFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetSensitiveDataModelSensitiveSchemasPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetSensitiveDataModelSensitiveSchemasPlainArgs Empty = new GetSensitiveDataModelSensitiveSchemasPlainArgs();

    @Import(name="filters")
    private @Nullable List<GetSensitiveDataModelSensitiveSchemasFilter> filters;

    public Optional<List<GetSensitiveDataModelSensitiveSchemasFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * A filter to return only items related to specific schema name.
     * 
     */
    @Import(name="schemaNames")
    private @Nullable List<String> schemaNames;

    /**
     * @return A filter to return only items related to specific schema name.
     * 
     */
    public Optional<List<String>> schemaNames() {
        return Optional.ofNullable(this.schemaNames);
    }

    /**
     * The OCID of the sensitive data model.
     * 
     */
    @Import(name="sensitiveDataModelId", required=true)
    private String sensitiveDataModelId;

    /**
     * @return The OCID of the sensitive data model.
     * 
     */
    public String sensitiveDataModelId() {
        return this.sensitiveDataModelId;
    }

    private GetSensitiveDataModelSensitiveSchemasPlainArgs() {}

    private GetSensitiveDataModelSensitiveSchemasPlainArgs(GetSensitiveDataModelSensitiveSchemasPlainArgs $) {
        this.filters = $.filters;
        this.schemaNames = $.schemaNames;
        this.sensitiveDataModelId = $.sensitiveDataModelId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetSensitiveDataModelSensitiveSchemasPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetSensitiveDataModelSensitiveSchemasPlainArgs $;

        public Builder() {
            $ = new GetSensitiveDataModelSensitiveSchemasPlainArgs();
        }

        public Builder(GetSensitiveDataModelSensitiveSchemasPlainArgs defaults) {
            $ = new GetSensitiveDataModelSensitiveSchemasPlainArgs(Objects.requireNonNull(defaults));
        }

        public Builder filters(@Nullable List<GetSensitiveDataModelSensitiveSchemasFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetSensitiveDataModelSensitiveSchemasFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param schemaNames A filter to return only items related to specific schema name.
         * 
         * @return builder
         * 
         */
        public Builder schemaNames(@Nullable List<String> schemaNames) {
            $.schemaNames = schemaNames;
            return this;
        }

        /**
         * @param schemaNames A filter to return only items related to specific schema name.
         * 
         * @return builder
         * 
         */
        public Builder schemaNames(String... schemaNames) {
            return schemaNames(List.of(schemaNames));
        }

        /**
         * @param sensitiveDataModelId The OCID of the sensitive data model.
         * 
         * @return builder
         * 
         */
        public Builder sensitiveDataModelId(String sensitiveDataModelId) {
            $.sensitiveDataModelId = sensitiveDataModelId;
            return this;
        }

        public GetSensitiveDataModelSensitiveSchemasPlainArgs build() {
            $.sensitiveDataModelId = Objects.requireNonNull($.sensitiveDataModelId, "expected parameter 'sensitiveDataModelId' to be non-null");
            return $;
        }
    }

}