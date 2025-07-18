// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetSoftwareUpdate.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class FsuCycleNextActionToExecuteArgs extends com.pulumi.resources.ResourceArgs {

    public static final FsuCycleNextActionToExecuteArgs Empty = new FsuCycleNextActionToExecuteArgs();

    /**
     * The date and time the Exadata Fleet Update Action is expected to start. [RFC 3339](https://tools.ietf.org/rfc/rfc3339), section 14.29.
     * 
     */
    @Import(name="timeToStart")
    private @Nullable Output<String> timeToStart;

    /**
     * @return The date and time the Exadata Fleet Update Action is expected to start. [RFC 3339](https://tools.ietf.org/rfc/rfc3339), section 14.29.
     * 
     */
    public Optional<Output<String>> timeToStart() {
        return Optional.ofNullable(this.timeToStart);
    }

    /**
     * (Updatable) Type of Exadata Fleet Update Cycle.
     * 
     */
    @Import(name="type")
    private @Nullable Output<String> type;

    /**
     * @return (Updatable) Type of Exadata Fleet Update Cycle.
     * 
     */
    public Optional<Output<String>> type() {
        return Optional.ofNullable(this.type);
    }

    private FsuCycleNextActionToExecuteArgs() {}

    private FsuCycleNextActionToExecuteArgs(FsuCycleNextActionToExecuteArgs $) {
        this.timeToStart = $.timeToStart;
        this.type = $.type;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(FsuCycleNextActionToExecuteArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private FsuCycleNextActionToExecuteArgs $;

        public Builder() {
            $ = new FsuCycleNextActionToExecuteArgs();
        }

        public Builder(FsuCycleNextActionToExecuteArgs defaults) {
            $ = new FsuCycleNextActionToExecuteArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param timeToStart The date and time the Exadata Fleet Update Action is expected to start. [RFC 3339](https://tools.ietf.org/rfc/rfc3339), section 14.29.
         * 
         * @return builder
         * 
         */
        public Builder timeToStart(@Nullable Output<String> timeToStart) {
            $.timeToStart = timeToStart;
            return this;
        }

        /**
         * @param timeToStart The date and time the Exadata Fleet Update Action is expected to start. [RFC 3339](https://tools.ietf.org/rfc/rfc3339), section 14.29.
         * 
         * @return builder
         * 
         */
        public Builder timeToStart(String timeToStart) {
            return timeToStart(Output.of(timeToStart));
        }

        /**
         * @param type (Updatable) Type of Exadata Fleet Update Cycle.
         * 
         * @return builder
         * 
         */
        public Builder type(@Nullable Output<String> type) {
            $.type = type;
            return this;
        }

        /**
         * @param type (Updatable) Type of Exadata Fleet Update Cycle.
         * 
         * @return builder
         * 
         */
        public Builder type(String type) {
            return type(Output.of(type));
        }

        public FsuCycleNextActionToExecuteArgs build() {
            return $;
        }
    }

}
