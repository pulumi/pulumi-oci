// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.MeteringComputation.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ScheduleQueryPropertiesDateRangeArgs extends com.pulumi.resources.ResourceArgs {

    public static final ScheduleQueryPropertiesDateRangeArgs Empty = new ScheduleQueryPropertiesDateRangeArgs();

    /**
     * Defines whether the schedule date range is STATIC or DYNAMIC.
     * 
     */
    @Import(name="dateRangeType", required=true)
    private Output<String> dateRangeType;

    /**
     * @return Defines whether the schedule date range is STATIC or DYNAMIC.
     * 
     */
    public Output<String> dateRangeType() {
        return this.dateRangeType;
    }

    @Import(name="dynamicDateRangeType")
    private @Nullable Output<String> dynamicDateRangeType;

    public Optional<Output<String>> dynamicDateRangeType() {
        return Optional.ofNullable(this.dynamicDateRangeType);
    }

    /**
     * The usage end time.
     * 
     */
    @Import(name="timeUsageEnded")
    private @Nullable Output<String> timeUsageEnded;

    /**
     * @return The usage end time.
     * 
     */
    public Optional<Output<String>> timeUsageEnded() {
        return Optional.ofNullable(this.timeUsageEnded);
    }

    /**
     * The usage start time.
     * 
     */
    @Import(name="timeUsageStarted")
    private @Nullable Output<String> timeUsageStarted;

    /**
     * @return The usage start time.
     * 
     */
    public Optional<Output<String>> timeUsageStarted() {
        return Optional.ofNullable(this.timeUsageStarted);
    }

    private ScheduleQueryPropertiesDateRangeArgs() {}

    private ScheduleQueryPropertiesDateRangeArgs(ScheduleQueryPropertiesDateRangeArgs $) {
        this.dateRangeType = $.dateRangeType;
        this.dynamicDateRangeType = $.dynamicDateRangeType;
        this.timeUsageEnded = $.timeUsageEnded;
        this.timeUsageStarted = $.timeUsageStarted;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ScheduleQueryPropertiesDateRangeArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ScheduleQueryPropertiesDateRangeArgs $;

        public Builder() {
            $ = new ScheduleQueryPropertiesDateRangeArgs();
        }

        public Builder(ScheduleQueryPropertiesDateRangeArgs defaults) {
            $ = new ScheduleQueryPropertiesDateRangeArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param dateRangeType Defines whether the schedule date range is STATIC or DYNAMIC.
         * 
         * @return builder
         * 
         */
        public Builder dateRangeType(Output<String> dateRangeType) {
            $.dateRangeType = dateRangeType;
            return this;
        }

        /**
         * @param dateRangeType Defines whether the schedule date range is STATIC or DYNAMIC.
         * 
         * @return builder
         * 
         */
        public Builder dateRangeType(String dateRangeType) {
            return dateRangeType(Output.of(dateRangeType));
        }

        public Builder dynamicDateRangeType(@Nullable Output<String> dynamicDateRangeType) {
            $.dynamicDateRangeType = dynamicDateRangeType;
            return this;
        }

        public Builder dynamicDateRangeType(String dynamicDateRangeType) {
            return dynamicDateRangeType(Output.of(dynamicDateRangeType));
        }

        /**
         * @param timeUsageEnded The usage end time.
         * 
         * @return builder
         * 
         */
        public Builder timeUsageEnded(@Nullable Output<String> timeUsageEnded) {
            $.timeUsageEnded = timeUsageEnded;
            return this;
        }

        /**
         * @param timeUsageEnded The usage end time.
         * 
         * @return builder
         * 
         */
        public Builder timeUsageEnded(String timeUsageEnded) {
            return timeUsageEnded(Output.of(timeUsageEnded));
        }

        /**
         * @param timeUsageStarted The usage start time.
         * 
         * @return builder
         * 
         */
        public Builder timeUsageStarted(@Nullable Output<String> timeUsageStarted) {
            $.timeUsageStarted = timeUsageStarted;
            return this;
        }

        /**
         * @param timeUsageStarted The usage start time.
         * 
         * @return builder
         * 
         */
        public Builder timeUsageStarted(String timeUsageStarted) {
            return timeUsageStarted(Output.of(timeUsageStarted));
        }

        public ScheduleQueryPropertiesDateRangeArgs build() {
            if ($.dateRangeType == null) {
                throw new MissingRequiredPropertyException("ScheduleQueryPropertiesDateRangeArgs", "dateRangeType");
            }
            return $;
        }
    }

}
