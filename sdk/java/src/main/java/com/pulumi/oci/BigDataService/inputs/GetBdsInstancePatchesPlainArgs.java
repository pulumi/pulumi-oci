// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.BigDataService.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.BigDataService.inputs.GetBdsInstancePatchesFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetBdsInstancePatchesPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetBdsInstancePatchesPlainArgs Empty = new GetBdsInstancePatchesPlainArgs();

    /**
     * The OCID of the cluster.
     * 
     */
    @Import(name="bdsInstanceId", required=true)
    private String bdsInstanceId;

    /**
     * @return The OCID of the cluster.
     * 
     */
    public String bdsInstanceId() {
        return this.bdsInstanceId;
    }

    @Import(name="filters")
    private @Nullable List<GetBdsInstancePatchesFilter> filters;

    public Optional<List<GetBdsInstancePatchesFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    private GetBdsInstancePatchesPlainArgs() {}

    private GetBdsInstancePatchesPlainArgs(GetBdsInstancePatchesPlainArgs $) {
        this.bdsInstanceId = $.bdsInstanceId;
        this.filters = $.filters;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetBdsInstancePatchesPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetBdsInstancePatchesPlainArgs $;

        public Builder() {
            $ = new GetBdsInstancePatchesPlainArgs();
        }

        public Builder(GetBdsInstancePatchesPlainArgs defaults) {
            $ = new GetBdsInstancePatchesPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param bdsInstanceId The OCID of the cluster.
         * 
         * @return builder
         * 
         */
        public Builder bdsInstanceId(String bdsInstanceId) {
            $.bdsInstanceId = bdsInstanceId;
            return this;
        }

        public Builder filters(@Nullable List<GetBdsInstancePatchesFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetBdsInstancePatchesFilter... filters) {
            return filters(List.of(filters));
        }

        public GetBdsInstancePatchesPlainArgs build() {
            if ($.bdsInstanceId == null) {
                throw new MissingRequiredPropertyException("GetBdsInstancePatchesPlainArgs", "bdsInstanceId");
            }
            return $;
        }
    }

}
