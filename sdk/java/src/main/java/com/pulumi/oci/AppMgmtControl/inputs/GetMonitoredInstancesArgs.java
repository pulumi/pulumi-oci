// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.AppMgmtControl.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.AppMgmtControl.inputs.GetMonitoredInstancesFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetMonitoredInstancesArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetMonitoredInstancesArgs Empty = new GetMonitoredInstancesArgs();

    /**
     * The ID of the compartment in which to list resources.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return The ID of the compartment in which to list resources.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * A filter to return only resources that match the entire display name given.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return A filter to return only resources that match the entire display name given.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    @Import(name="filters")
    private @Nullable Output<List<GetMonitoredInstancesFilterArgs>> filters;

    public Optional<Output<List<GetMonitoredInstancesFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    private GetMonitoredInstancesArgs() {}

    private GetMonitoredInstancesArgs(GetMonitoredInstancesArgs $) {
        this.compartmentId = $.compartmentId;
        this.displayName = $.displayName;
        this.filters = $.filters;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetMonitoredInstancesArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetMonitoredInstancesArgs $;

        public Builder() {
            $ = new GetMonitoredInstancesArgs();
        }

        public Builder(GetMonitoredInstancesArgs defaults) {
            $ = new GetMonitoredInstancesArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The ID of the compartment in which to list resources.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The ID of the compartment in which to list resources.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param displayName A filter to return only resources that match the entire display name given.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName A filter to return only resources that match the entire display name given.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        public Builder filters(@Nullable Output<List<GetMonitoredInstancesFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetMonitoredInstancesFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetMonitoredInstancesFilterArgs... filters) {
            return filters(List.of(filters));
        }

        public GetMonitoredInstancesArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetMonitoredInstancesArgs", "compartmentId");
            }
            return $;
        }
    }

}
