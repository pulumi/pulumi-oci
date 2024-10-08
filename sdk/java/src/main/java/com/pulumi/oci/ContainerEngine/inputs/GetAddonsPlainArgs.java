// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ContainerEngine.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.ContainerEngine.inputs.GetAddonsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetAddonsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetAddonsPlainArgs Empty = new GetAddonsPlainArgs();

    /**
     * The OCID of the cluster.
     * 
     */
    @Import(name="clusterId", required=true)
    private String clusterId;

    /**
     * @return The OCID of the cluster.
     * 
     */
    public String clusterId() {
        return this.clusterId;
    }

    @Import(name="filters")
    private @Nullable List<GetAddonsFilter> filters;

    public Optional<List<GetAddonsFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    private GetAddonsPlainArgs() {}

    private GetAddonsPlainArgs(GetAddonsPlainArgs $) {
        this.clusterId = $.clusterId;
        this.filters = $.filters;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetAddonsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetAddonsPlainArgs $;

        public Builder() {
            $ = new GetAddonsPlainArgs();
        }

        public Builder(GetAddonsPlainArgs defaults) {
            $ = new GetAddonsPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param clusterId The OCID of the cluster.
         * 
         * @return builder
         * 
         */
        public Builder clusterId(String clusterId) {
            $.clusterId = clusterId;
            return this;
        }

        public Builder filters(@Nullable List<GetAddonsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetAddonsFilter... filters) {
            return filters(List.of(filters));
        }

        public GetAddonsPlainArgs build() {
            if ($.clusterId == null) {
                throw new MissingRequiredPropertyException("GetAddonsPlainArgs", "clusterId");
            }
            return $;
        }
    }

}
