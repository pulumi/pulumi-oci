// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.StackMonitoring.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.oci.StackMonitoring.inputs.GetDiscoveryJobsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetDiscoveryJobsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetDiscoveryJobsPlainArgs Empty = new GetDiscoveryJobsPlainArgs();

    /**
     * The ID of the compartment in which data is listed.
     * 
     */
    @Import(name="compartmentId", required=true)
    private String compartmentId;

    /**
     * @return The ID of the compartment in which data is listed.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }

    @Import(name="filters")
    private @Nullable List<GetDiscoveryJobsFilter> filters;

    public Optional<List<GetDiscoveryJobsFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * A filter to return only discovery jobs that match the entire resource name given.
     * 
     */
    @Import(name="name")
    private @Nullable String name;

    /**
     * @return A filter to return only discovery jobs that match the entire resource name given.
     * 
     */
    public Optional<String> name() {
        return Optional.ofNullable(this.name);
    }

    private GetDiscoveryJobsPlainArgs() {}

    private GetDiscoveryJobsPlainArgs(GetDiscoveryJobsPlainArgs $) {
        this.compartmentId = $.compartmentId;
        this.filters = $.filters;
        this.name = $.name;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetDiscoveryJobsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetDiscoveryJobsPlainArgs $;

        public Builder() {
            $ = new GetDiscoveryJobsPlainArgs();
        }

        public Builder(GetDiscoveryJobsPlainArgs defaults) {
            $ = new GetDiscoveryJobsPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The ID of the compartment in which data is listed.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        public Builder filters(@Nullable List<GetDiscoveryJobsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetDiscoveryJobsFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param name A filter to return only discovery jobs that match the entire resource name given.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable String name) {
            $.name = name;
            return this;
        }

        public GetDiscoveryJobsPlainArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            return $;
        }
    }

}