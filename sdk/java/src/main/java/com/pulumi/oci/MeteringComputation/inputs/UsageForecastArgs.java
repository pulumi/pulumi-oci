// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.MeteringComputation.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class UsageForecastArgs extends com.pulumi.resources.ResourceArgs {

    public static final UsageForecastArgs Empty = new UsageForecastArgs();

    /**
     * BASIC uses the exponential smoothing (ETS) model to project future usage/costs based on history data. The basis for projections is a periodic set of equivalent historical days for which the projection is being made.
     * 
     */
    @Import(name="forecastType")
    private @Nullable Output<String> forecastType;

    /**
     * @return BASIC uses the exponential smoothing (ETS) model to project future usage/costs based on history data. The basis for projections is a periodic set of equivalent historical days for which the projection is being made.
     * 
     */
    public Optional<Output<String>> forecastType() {
        return Optional.ofNullable(this.forecastType);
    }

    /**
     * The forecast end time.
     * 
     */
    @Import(name="timeForecastEnded", required=true)
    private Output<String> timeForecastEnded;

    /**
     * @return The forecast end time.
     * 
     */
    public Output<String> timeForecastEnded() {
        return this.timeForecastEnded;
    }

    /**
     * The forecast start time. Defaults to UTC-1 if not specified.
     * 
     */
    @Import(name="timeForecastStarted")
    private @Nullable Output<String> timeForecastStarted;

    /**
     * @return The forecast start time. Defaults to UTC-1 if not specified.
     * 
     */
    public Optional<Output<String>> timeForecastStarted() {
        return Optional.ofNullable(this.timeForecastStarted);
    }

    private UsageForecastArgs() {}

    private UsageForecastArgs(UsageForecastArgs $) {
        this.forecastType = $.forecastType;
        this.timeForecastEnded = $.timeForecastEnded;
        this.timeForecastStarted = $.timeForecastStarted;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(UsageForecastArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private UsageForecastArgs $;

        public Builder() {
            $ = new UsageForecastArgs();
        }

        public Builder(UsageForecastArgs defaults) {
            $ = new UsageForecastArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param forecastType BASIC uses the exponential smoothing (ETS) model to project future usage/costs based on history data. The basis for projections is a periodic set of equivalent historical days for which the projection is being made.
         * 
         * @return builder
         * 
         */
        public Builder forecastType(@Nullable Output<String> forecastType) {
            $.forecastType = forecastType;
            return this;
        }

        /**
         * @param forecastType BASIC uses the exponential smoothing (ETS) model to project future usage/costs based on history data. The basis for projections is a periodic set of equivalent historical days for which the projection is being made.
         * 
         * @return builder
         * 
         */
        public Builder forecastType(String forecastType) {
            return forecastType(Output.of(forecastType));
        }

        /**
         * @param timeForecastEnded The forecast end time.
         * 
         * @return builder
         * 
         */
        public Builder timeForecastEnded(Output<String> timeForecastEnded) {
            $.timeForecastEnded = timeForecastEnded;
            return this;
        }

        /**
         * @param timeForecastEnded The forecast end time.
         * 
         * @return builder
         * 
         */
        public Builder timeForecastEnded(String timeForecastEnded) {
            return timeForecastEnded(Output.of(timeForecastEnded));
        }

        /**
         * @param timeForecastStarted The forecast start time. Defaults to UTC-1 if not specified.
         * 
         * @return builder
         * 
         */
        public Builder timeForecastStarted(@Nullable Output<String> timeForecastStarted) {
            $.timeForecastStarted = timeForecastStarted;
            return this;
        }

        /**
         * @param timeForecastStarted The forecast start time. Defaults to UTC-1 if not specified.
         * 
         * @return builder
         * 
         */
        public Builder timeForecastStarted(String timeForecastStarted) {
            return timeForecastStarted(Output.of(timeForecastStarted));
        }

        public UsageForecastArgs build() {
            $.timeForecastEnded = Objects.requireNonNull($.timeForecastEnded, "expected parameter 'timeForecastEnded' to be non-null");
            return $;
        }
    }

}