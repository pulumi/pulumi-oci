// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DataSafe.inputs.GetMaskingPolicyMaskingSchemasFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetMaskingPolicyMaskingSchemasPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetMaskingPolicyMaskingSchemasPlainArgs Empty = new GetMaskingPolicyMaskingSchemasPlainArgs();

    @Import(name="filters")
    private @Nullable List<GetMaskingPolicyMaskingSchemasFilter> filters;

    public Optional<List<GetMaskingPolicyMaskingSchemasFilter>> filters() {
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

    private GetMaskingPolicyMaskingSchemasPlainArgs() {}

    private GetMaskingPolicyMaskingSchemasPlainArgs(GetMaskingPolicyMaskingSchemasPlainArgs $) {
        this.filters = $.filters;
        this.maskingPolicyId = $.maskingPolicyId;
        this.schemaNames = $.schemaNames;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetMaskingPolicyMaskingSchemasPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetMaskingPolicyMaskingSchemasPlainArgs $;

        public Builder() {
            $ = new GetMaskingPolicyMaskingSchemasPlainArgs();
        }

        public Builder(GetMaskingPolicyMaskingSchemasPlainArgs defaults) {
            $ = new GetMaskingPolicyMaskingSchemasPlainArgs(Objects.requireNonNull(defaults));
        }

        public Builder filters(@Nullable List<GetMaskingPolicyMaskingSchemasFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetMaskingPolicyMaskingSchemasFilter... filters) {
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

        public GetMaskingPolicyMaskingSchemasPlainArgs build() {
            $.maskingPolicyId = Objects.requireNonNull($.maskingPolicyId, "expected parameter 'maskingPolicyId' to be non-null");
            return $;
        }
    }

}