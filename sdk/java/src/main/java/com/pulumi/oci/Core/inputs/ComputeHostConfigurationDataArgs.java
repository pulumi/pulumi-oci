// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Core.inputs.ComputeHostConfigurationDataCheckDetailArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ComputeHostConfigurationDataArgs extends com.pulumi.resources.ResourceArgs {

    public static final ComputeHostConfigurationDataArgs Empty = new ComputeHostConfigurationDataArgs();

    /**
     * Compute Host Group Configuration Details Check
     * 
     */
    @Import(name="checkDetails")
    private @Nullable Output<List<ComputeHostConfigurationDataCheckDetailArgs>> checkDetails;

    /**
     * @return Compute Host Group Configuration Details Check
     * 
     */
    public Optional<Output<List<ComputeHostConfigurationDataCheckDetailArgs>>> checkDetails() {
        return Optional.ofNullable(this.checkDetails);
    }

    /**
     * The time that was last applied.
     * 
     */
    @Import(name="timeLastApply")
    private @Nullable Output<String> timeLastApply;

    /**
     * @return The time that was last applied.
     * 
     */
    public Optional<Output<String>> timeLastApply() {
        return Optional.ofNullable(this.timeLastApply);
    }

    private ComputeHostConfigurationDataArgs() {}

    private ComputeHostConfigurationDataArgs(ComputeHostConfigurationDataArgs $) {
        this.checkDetails = $.checkDetails;
        this.timeLastApply = $.timeLastApply;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ComputeHostConfigurationDataArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ComputeHostConfigurationDataArgs $;

        public Builder() {
            $ = new ComputeHostConfigurationDataArgs();
        }

        public Builder(ComputeHostConfigurationDataArgs defaults) {
            $ = new ComputeHostConfigurationDataArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param checkDetails Compute Host Group Configuration Details Check
         * 
         * @return builder
         * 
         */
        public Builder checkDetails(@Nullable Output<List<ComputeHostConfigurationDataCheckDetailArgs>> checkDetails) {
            $.checkDetails = checkDetails;
            return this;
        }

        /**
         * @param checkDetails Compute Host Group Configuration Details Check
         * 
         * @return builder
         * 
         */
        public Builder checkDetails(List<ComputeHostConfigurationDataCheckDetailArgs> checkDetails) {
            return checkDetails(Output.of(checkDetails));
        }

        /**
         * @param checkDetails Compute Host Group Configuration Details Check
         * 
         * @return builder
         * 
         */
        public Builder checkDetails(ComputeHostConfigurationDataCheckDetailArgs... checkDetails) {
            return checkDetails(List.of(checkDetails));
        }

        /**
         * @param timeLastApply The time that was last applied.
         * 
         * @return builder
         * 
         */
        public Builder timeLastApply(@Nullable Output<String> timeLastApply) {
            $.timeLastApply = timeLastApply;
            return this;
        }

        /**
         * @param timeLastApply The time that was last applied.
         * 
         * @return builder
         * 
         */
        public Builder timeLastApply(String timeLastApply) {
            return timeLastApply(Output.of(timeLastApply));
        }

        public ComputeHostConfigurationDataArgs build() {
            return $;
        }
    }

}
