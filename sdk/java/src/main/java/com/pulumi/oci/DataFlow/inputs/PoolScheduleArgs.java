// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataFlow.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class PoolScheduleArgs extends com.pulumi.resources.ResourceArgs {

    public static final PoolScheduleArgs Empty = new PoolScheduleArgs();

    /**
     * (Updatable) Day of the week SUN-SAT
     * 
     */
    @Import(name="dayOfWeek")
    private @Nullable Output<String> dayOfWeek;

    /**
     * @return (Updatable) Day of the week SUN-SAT
     * 
     */
    public Optional<Output<String>> dayOfWeek() {
        return Optional.ofNullable(this.dayOfWeek);
    }

    /**
     * (Updatable) Hour of the day to start or stop pool.
     * 
     */
    @Import(name="startTime")
    private @Nullable Output<Integer> startTime;

    /**
     * @return (Updatable) Hour of the day to start or stop pool.
     * 
     */
    public Optional<Output<Integer>> startTime() {
        return Optional.ofNullable(this.startTime);
    }

    /**
     * (Updatable) Hour of the day to stop the pool.
     * 
     */
    @Import(name="stopTime")
    private @Nullable Output<Integer> stopTime;

    /**
     * @return (Updatable) Hour of the day to stop the pool.
     * 
     */
    public Optional<Output<Integer>> stopTime() {
        return Optional.ofNullable(this.stopTime);
    }

    private PoolScheduleArgs() {}

    private PoolScheduleArgs(PoolScheduleArgs $) {
        this.dayOfWeek = $.dayOfWeek;
        this.startTime = $.startTime;
        this.stopTime = $.stopTime;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(PoolScheduleArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private PoolScheduleArgs $;

        public Builder() {
            $ = new PoolScheduleArgs();
        }

        public Builder(PoolScheduleArgs defaults) {
            $ = new PoolScheduleArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param dayOfWeek (Updatable) Day of the week SUN-SAT
         * 
         * @return builder
         * 
         */
        public Builder dayOfWeek(@Nullable Output<String> dayOfWeek) {
            $.dayOfWeek = dayOfWeek;
            return this;
        }

        /**
         * @param dayOfWeek (Updatable) Day of the week SUN-SAT
         * 
         * @return builder
         * 
         */
        public Builder dayOfWeek(String dayOfWeek) {
            return dayOfWeek(Output.of(dayOfWeek));
        }

        /**
         * @param startTime (Updatable) Hour of the day to start or stop pool.
         * 
         * @return builder
         * 
         */
        public Builder startTime(@Nullable Output<Integer> startTime) {
            $.startTime = startTime;
            return this;
        }

        /**
         * @param startTime (Updatable) Hour of the day to start or stop pool.
         * 
         * @return builder
         * 
         */
        public Builder startTime(Integer startTime) {
            return startTime(Output.of(startTime));
        }

        /**
         * @param stopTime (Updatable) Hour of the day to stop the pool.
         * 
         * @return builder
         * 
         */
        public Builder stopTime(@Nullable Output<Integer> stopTime) {
            $.stopTime = stopTime;
            return this;
        }

        /**
         * @param stopTime (Updatable) Hour of the day to stop the pool.
         * 
         * @return builder
         * 
         */
        public Builder stopTime(Integer stopTime) {
            return stopTime(Output.of(stopTime));
        }

        public PoolScheduleArgs build() {
            return $;
        }
    }

}