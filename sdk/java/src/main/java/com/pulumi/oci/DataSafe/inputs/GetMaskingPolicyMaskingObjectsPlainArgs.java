// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DataSafe.inputs.GetMaskingPolicyMaskingObjectsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetMaskingPolicyMaskingObjectsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetMaskingPolicyMaskingObjectsPlainArgs Empty = new GetMaskingPolicyMaskingObjectsPlainArgs();

    @Import(name="filters")
    private @Nullable List<GetMaskingPolicyMaskingObjectsFilter> filters;

    public Optional<List<GetMaskingPolicyMaskingObjectsFilter>> filters() {
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
     * A filter to return only items related to a specific object type.
     * 
     */
    @Import(name="objectTypes")
    private @Nullable List<String> objectTypes;

    /**
     * @return A filter to return only items related to a specific object type.
     * 
     */
    public Optional<List<String>> objectTypes() {
        return Optional.ofNullable(this.objectTypes);
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

    private GetMaskingPolicyMaskingObjectsPlainArgs() {}

    private GetMaskingPolicyMaskingObjectsPlainArgs(GetMaskingPolicyMaskingObjectsPlainArgs $) {
        this.filters = $.filters;
        this.maskingPolicyId = $.maskingPolicyId;
        this.objectTypes = $.objectTypes;
        this.objects = $.objects;
        this.schemaNames = $.schemaNames;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetMaskingPolicyMaskingObjectsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetMaskingPolicyMaskingObjectsPlainArgs $;

        public Builder() {
            $ = new GetMaskingPolicyMaskingObjectsPlainArgs();
        }

        public Builder(GetMaskingPolicyMaskingObjectsPlainArgs defaults) {
            $ = new GetMaskingPolicyMaskingObjectsPlainArgs(Objects.requireNonNull(defaults));
        }

        public Builder filters(@Nullable List<GetMaskingPolicyMaskingObjectsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetMaskingPolicyMaskingObjectsFilter... filters) {
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
         * @param objectTypes A filter to return only items related to a specific object type.
         * 
         * @return builder
         * 
         */
        public Builder objectTypes(@Nullable List<String> objectTypes) {
            $.objectTypes = objectTypes;
            return this;
        }

        /**
         * @param objectTypes A filter to return only items related to a specific object type.
         * 
         * @return builder
         * 
         */
        public Builder objectTypes(String... objectTypes) {
            return objectTypes(List.of(objectTypes));
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

        public GetMaskingPolicyMaskingObjectsPlainArgs build() {
            $.maskingPolicyId = Objects.requireNonNull($.maskingPolicyId, "expected parameter 'maskingPolicyId' to be non-null");
            return $;
        }
    }

}