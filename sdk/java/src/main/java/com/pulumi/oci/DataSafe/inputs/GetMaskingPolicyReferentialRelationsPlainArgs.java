// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DataSafe.inputs.GetMaskingPolicyReferentialRelationsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetMaskingPolicyReferentialRelationsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetMaskingPolicyReferentialRelationsPlainArgs Empty = new GetMaskingPolicyReferentialRelationsPlainArgs();

    /**
     * A filter to return only a specific column based on column name.
     * 
     */
    @Import(name="columnNames")
    private @Nullable List<String> columnNames;

    /**
     * @return A filter to return only a specific column based on column name.
     * 
     */
    public Optional<List<String>> columnNames() {
        return Optional.ofNullable(this.columnNames);
    }

    @Import(name="filters")
    private @Nullable List<GetMaskingPolicyReferentialRelationsFilter> filters;

    public Optional<List<GetMaskingPolicyReferentialRelationsFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The OCID of the masking policy.
     * 
     */
    @Import(name="maskingPolicyId", required=true)
    private String maskingPolicyId;

    /**
     * @return The OCID of the masking policy.
     * 
     */
    public String maskingPolicyId() {
        return this.maskingPolicyId;
    }

    /**
     * A filter to return only items related to a specific object name.
     * 
     */
    @Import(name="objects")
    private @Nullable List<String> objects;

    /**
     * @return A filter to return only items related to a specific object name.
     * 
     */
    public Optional<List<String>> objects() {
        return Optional.ofNullable(this.objects);
    }

    /**
     * A filter to return columns based on their relationship with their parent columns. If set to NONE, it returns the columns that do not have any parent. The response includes the parent columns as well as the independent columns that are not in any relationship. If set to APP_DEFINED, it returns all the child columns that have application-level (non-dictionary) relationship with their parents. If set to DB_DEFINED, it returns all the child columns that have database-level (dictionary-defined) relationship with their parents.
     * 
     */
    @Import(name="relationTypes")
    private @Nullable List<String> relationTypes;

    /**
     * @return A filter to return columns based on their relationship with their parent columns. If set to NONE, it returns the columns that do not have any parent. The response includes the parent columns as well as the independent columns that are not in any relationship. If set to APP_DEFINED, it returns all the child columns that have application-level (non-dictionary) relationship with their parents. If set to DB_DEFINED, it returns all the child columns that have database-level (dictionary-defined) relationship with their parents.
     * 
     */
    public Optional<List<String>> relationTypes() {
        return Optional.ofNullable(this.relationTypes);
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

    private GetMaskingPolicyReferentialRelationsPlainArgs() {}

    private GetMaskingPolicyReferentialRelationsPlainArgs(GetMaskingPolicyReferentialRelationsPlainArgs $) {
        this.columnNames = $.columnNames;
        this.filters = $.filters;
        this.maskingPolicyId = $.maskingPolicyId;
        this.objects = $.objects;
        this.relationTypes = $.relationTypes;
        this.schemaNames = $.schemaNames;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetMaskingPolicyReferentialRelationsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetMaskingPolicyReferentialRelationsPlainArgs $;

        public Builder() {
            $ = new GetMaskingPolicyReferentialRelationsPlainArgs();
        }

        public Builder(GetMaskingPolicyReferentialRelationsPlainArgs defaults) {
            $ = new GetMaskingPolicyReferentialRelationsPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param columnNames A filter to return only a specific column based on column name.
         * 
         * @return builder
         * 
         */
        public Builder columnNames(@Nullable List<String> columnNames) {
            $.columnNames = columnNames;
            return this;
        }

        /**
         * @param columnNames A filter to return only a specific column based on column name.
         * 
         * @return builder
         * 
         */
        public Builder columnNames(String... columnNames) {
            return columnNames(List.of(columnNames));
        }

        public Builder filters(@Nullable List<GetMaskingPolicyReferentialRelationsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetMaskingPolicyReferentialRelationsFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param maskingPolicyId The OCID of the masking policy.
         * 
         * @return builder
         * 
         */
        public Builder maskingPolicyId(String maskingPolicyId) {
            $.maskingPolicyId = maskingPolicyId;
            return this;
        }

        /**
         * @param objects A filter to return only items related to a specific object name.
         * 
         * @return builder
         * 
         */
        public Builder objects(@Nullable List<String> objects) {
            $.objects = objects;
            return this;
        }

        /**
         * @param objects A filter to return only items related to a specific object name.
         * 
         * @return builder
         * 
         */
        public Builder objects(String... objects) {
            return objects(List.of(objects));
        }

        /**
         * @param relationTypes A filter to return columns based on their relationship with their parent columns. If set to NONE, it returns the columns that do not have any parent. The response includes the parent columns as well as the independent columns that are not in any relationship. If set to APP_DEFINED, it returns all the child columns that have application-level (non-dictionary) relationship with their parents. If set to DB_DEFINED, it returns all the child columns that have database-level (dictionary-defined) relationship with their parents.
         * 
         * @return builder
         * 
         */
        public Builder relationTypes(@Nullable List<String> relationTypes) {
            $.relationTypes = relationTypes;
            return this;
        }

        /**
         * @param relationTypes A filter to return columns based on their relationship with their parent columns. If set to NONE, it returns the columns that do not have any parent. The response includes the parent columns as well as the independent columns that are not in any relationship. If set to APP_DEFINED, it returns all the child columns that have application-level (non-dictionary) relationship with their parents. If set to DB_DEFINED, it returns all the child columns that have database-level (dictionary-defined) relationship with their parents.
         * 
         * @return builder
         * 
         */
        public Builder relationTypes(String... relationTypes) {
            return relationTypes(List.of(relationTypes));
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

        public GetMaskingPolicyReferentialRelationsPlainArgs build() {
            if ($.maskingPolicyId == null) {
                throw new MissingRequiredPropertyException("GetMaskingPolicyReferentialRelationsPlainArgs", "maskingPolicyId");
            }
            return $;
        }
    }

}
