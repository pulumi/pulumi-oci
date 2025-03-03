// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.StackMonitoring.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.StackMonitoring.inputs.GetMonitoredResourceTasksFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetMonitoredResourceTasksArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetMonitoredResourceTasksArgs Empty = new GetMonitoredResourceTasksArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment for which  stack monitoring resource tasks should be listed.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment for which  stack monitoring resource tasks should be listed.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    @Import(name="filters")
    private @Nullable Output<List<GetMonitoredResourceTasksFilterArgs>> filters;

    public Optional<Output<List<GetMonitoredResourceTasksFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * A filter to return only resources that matches with lifecycleState given.
     * 
     */
    @Import(name="status")
    private @Nullable Output<String> status;

    /**
     * @return A filter to return only resources that matches with lifecycleState given.
     * 
     */
    public Optional<Output<String>> status() {
        return Optional.ofNullable(this.status);
    }

    private GetMonitoredResourceTasksArgs() {}

    private GetMonitoredResourceTasksArgs(GetMonitoredResourceTasksArgs $) {
        this.compartmentId = $.compartmentId;
        this.filters = $.filters;
        this.status = $.status;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetMonitoredResourceTasksArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetMonitoredResourceTasksArgs $;

        public Builder() {
            $ = new GetMonitoredResourceTasksArgs();
        }

        public Builder(GetMonitoredResourceTasksArgs defaults) {
            $ = new GetMonitoredResourceTasksArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment for which  stack monitoring resource tasks should be listed.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment for which  stack monitoring resource tasks should be listed.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        public Builder filters(@Nullable Output<List<GetMonitoredResourceTasksFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetMonitoredResourceTasksFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetMonitoredResourceTasksFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param status A filter to return only resources that matches with lifecycleState given.
         * 
         * @return builder
         * 
         */
        public Builder status(@Nullable Output<String> status) {
            $.status = status;
            return this;
        }

        /**
         * @param status A filter to return only resources that matches with lifecycleState given.
         * 
         * @return builder
         * 
         */
        public Builder status(String status) {
            return status(Output.of(status));
        }

        public GetMonitoredResourceTasksArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetMonitoredResourceTasksArgs", "compartmentId");
            }
            return $;
        }
    }

}
