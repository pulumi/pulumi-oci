// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.BigDataService.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.BigDataService.inputs.GetAutoScalingConfigurationsFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetAutoScalingConfigurationsArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetAutoScalingConfigurationsArgs Empty = new GetAutoScalingConfigurationsArgs();

    @Import(name="bdsInstanceId", required=true)
    private Output<String> bdsInstanceId;

    public Output<String> bdsInstanceId() {
        return this.bdsInstanceId;
    }

    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    @Import(name="filters")
    private @Nullable Output<List<GetAutoScalingConfigurationsFilterArgs>> filters;

    public Optional<Output<List<GetAutoScalingConfigurationsFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    @Import(name="state")
    private @Nullable Output<String> state;

    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    private GetAutoScalingConfigurationsArgs() {}

    private GetAutoScalingConfigurationsArgs(GetAutoScalingConfigurationsArgs $) {
        this.bdsInstanceId = $.bdsInstanceId;
        this.compartmentId = $.compartmentId;
        this.displayName = $.displayName;
        this.filters = $.filters;
        this.state = $.state;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetAutoScalingConfigurationsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetAutoScalingConfigurationsArgs $;

        public Builder() {
            $ = new GetAutoScalingConfigurationsArgs();
        }

        public Builder(GetAutoScalingConfigurationsArgs defaults) {
            $ = new GetAutoScalingConfigurationsArgs(Objects.requireNonNull(defaults));
        }

        public Builder bdsInstanceId(Output<String> bdsInstanceId) {
            $.bdsInstanceId = bdsInstanceId;
            return this;
        }

        public Builder bdsInstanceId(String bdsInstanceId) {
            return bdsInstanceId(Output.of(bdsInstanceId));
        }

        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        public Builder filters(@Nullable Output<List<GetAutoScalingConfigurationsFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetAutoScalingConfigurationsFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetAutoScalingConfigurationsFilterArgs... filters) {
            return filters(List.of(filters));
        }

        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        public Builder state(String state) {
            return state(Output.of(state));
        }

        public GetAutoScalingConfigurationsArgs build() {
            if ($.bdsInstanceId == null) {
                throw new MissingRequiredPropertyException("GetAutoScalingConfigurationsArgs", "bdsInstanceId");
            }
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetAutoScalingConfigurationsArgs", "compartmentId");
            }
            return $;
        }
    }

}
