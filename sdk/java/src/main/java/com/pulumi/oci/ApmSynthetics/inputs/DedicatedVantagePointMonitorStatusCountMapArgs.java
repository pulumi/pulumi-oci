// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApmSynthetics.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Integer;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DedicatedVantagePointMonitorStatusCountMapArgs extends com.pulumi.resources.ResourceArgs {

    public static final DedicatedVantagePointMonitorStatusCountMapArgs Empty = new DedicatedVantagePointMonitorStatusCountMapArgs();

    /**
     * Number of disabled monitors using the script.
     * 
     */
    @Import(name="disabled")
    private @Nullable Output<Integer> disabled;

    /**
     * @return Number of disabled monitors using the script.
     * 
     */
    public Optional<Output<Integer>> disabled() {
        return Optional.ofNullable(this.disabled);
    }

    /**
     * Number of enabled monitors using the script.
     * 
     */
    @Import(name="enabled")
    private @Nullable Output<Integer> enabled;

    /**
     * @return Number of enabled monitors using the script.
     * 
     */
    public Optional<Output<Integer>> enabled() {
        return Optional.ofNullable(this.enabled);
    }

    /**
     * Number of invalid monitors using the script.
     * 
     */
    @Import(name="invalid")
    private @Nullable Output<Integer> invalid;

    /**
     * @return Number of invalid monitors using the script.
     * 
     */
    public Optional<Output<Integer>> invalid() {
        return Optional.ofNullable(this.invalid);
    }

    /**
     * Total number of monitors using the script.
     * 
     */
    @Import(name="total")
    private @Nullable Output<Integer> total;

    /**
     * @return Total number of monitors using the script.
     * 
     */
    public Optional<Output<Integer>> total() {
        return Optional.ofNullable(this.total);
    }

    private DedicatedVantagePointMonitorStatusCountMapArgs() {}

    private DedicatedVantagePointMonitorStatusCountMapArgs(DedicatedVantagePointMonitorStatusCountMapArgs $) {
        this.disabled = $.disabled;
        this.enabled = $.enabled;
        this.invalid = $.invalid;
        this.total = $.total;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DedicatedVantagePointMonitorStatusCountMapArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DedicatedVantagePointMonitorStatusCountMapArgs $;

        public Builder() {
            $ = new DedicatedVantagePointMonitorStatusCountMapArgs();
        }

        public Builder(DedicatedVantagePointMonitorStatusCountMapArgs defaults) {
            $ = new DedicatedVantagePointMonitorStatusCountMapArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param disabled Number of disabled monitors using the script.
         * 
         * @return builder
         * 
         */
        public Builder disabled(@Nullable Output<Integer> disabled) {
            $.disabled = disabled;
            return this;
        }

        /**
         * @param disabled Number of disabled monitors using the script.
         * 
         * @return builder
         * 
         */
        public Builder disabled(Integer disabled) {
            return disabled(Output.of(disabled));
        }

        /**
         * @param enabled Number of enabled monitors using the script.
         * 
         * @return builder
         * 
         */
        public Builder enabled(@Nullable Output<Integer> enabled) {
            $.enabled = enabled;
            return this;
        }

        /**
         * @param enabled Number of enabled monitors using the script.
         * 
         * @return builder
         * 
         */
        public Builder enabled(Integer enabled) {
            return enabled(Output.of(enabled));
        }

        /**
         * @param invalid Number of invalid monitors using the script.
         * 
         * @return builder
         * 
         */
        public Builder invalid(@Nullable Output<Integer> invalid) {
            $.invalid = invalid;
            return this;
        }

        /**
         * @param invalid Number of invalid monitors using the script.
         * 
         * @return builder
         * 
         */
        public Builder invalid(Integer invalid) {
            return invalid(Output.of(invalid));
        }

        /**
         * @param total Total number of monitors using the script.
         * 
         * @return builder
         * 
         */
        public Builder total(@Nullable Output<Integer> total) {
            $.total = total;
            return this;
        }

        /**
         * @param total Total number of monitors using the script.
         * 
         * @return builder
         * 
         */
        public Builder total(Integer total) {
            return total(Output.of(total));
        }

        public DedicatedVantagePointMonitorStatusCountMapArgs build() {
            return $;
        }
    }

}