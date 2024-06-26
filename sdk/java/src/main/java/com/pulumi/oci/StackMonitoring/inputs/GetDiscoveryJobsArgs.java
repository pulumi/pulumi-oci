// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.StackMonitoring.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.StackMonitoring.inputs.GetDiscoveryJobsFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetDiscoveryJobsArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetDiscoveryJobsArgs Empty = new GetDiscoveryJobsArgs();

    /**
     * The ID of the compartment in which data is listed.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return The ID of the compartment in which data is listed.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    @Import(name="filters")
    private @Nullable Output<List<GetDiscoveryJobsFilterArgs>> filters;

    public Optional<Output<List<GetDiscoveryJobsFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * A filter to return only discovery jobs that match the entire resource name given.
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return A filter to return only discovery jobs that match the entire resource name given.
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    private GetDiscoveryJobsArgs() {}

    private GetDiscoveryJobsArgs(GetDiscoveryJobsArgs $) {
        this.compartmentId = $.compartmentId;
        this.filters = $.filters;
        this.name = $.name;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetDiscoveryJobsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetDiscoveryJobsArgs $;

        public Builder() {
            $ = new GetDiscoveryJobsArgs();
        }

        public Builder(GetDiscoveryJobsArgs defaults) {
            $ = new GetDiscoveryJobsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The ID of the compartment in which data is listed.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The ID of the compartment in which data is listed.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        public Builder filters(@Nullable Output<List<GetDiscoveryJobsFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetDiscoveryJobsFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetDiscoveryJobsFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param name A filter to return only discovery jobs that match the entire resource name given.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name A filter to return only discovery jobs that match the entire resource name given.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        public GetDiscoveryJobsArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetDiscoveryJobsArgs", "compartmentId");
            }
            return $;
        }
    }

}
