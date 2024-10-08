// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.AiDocument.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.AiDocument.inputs.ProcessorJobInputLocationArgs;
import com.pulumi.oci.AiDocument.inputs.ProcessorJobOutputLocationArgs;
import com.pulumi.oci.AiDocument.inputs.ProcessorJobProcessorConfigArgs;
import java.lang.Double;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ProcessorJobState extends com.pulumi.resources.ResourceArgs {

    public static final ProcessorJobState Empty = new ProcessorJobState();

    /**
     * The compartment identifier.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return The compartment identifier.
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    /**
     * The display name of the processor job.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return The display name of the processor job.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * The location of the inputs.
     * 
     */
    @Import(name="inputLocation")
    private @Nullable Output<ProcessorJobInputLocationArgs> inputLocation;

    /**
     * @return The location of the inputs.
     * 
     */
    public Optional<Output<ProcessorJobInputLocationArgs>> inputLocation() {
        return Optional.ofNullable(this.inputLocation);
    }

    /**
     * The detailed status of FAILED state.
     * 
     */
    @Import(name="lifecycleDetails")
    private @Nullable Output<String> lifecycleDetails;

    /**
     * @return The detailed status of FAILED state.
     * 
     */
    public Optional<Output<String>> lifecycleDetails() {
        return Optional.ofNullable(this.lifecycleDetails);
    }

    /**
     * The object storage location where to store analysis results.
     * 
     */
    @Import(name="outputLocation")
    private @Nullable Output<ProcessorJobOutputLocationArgs> outputLocation;

    /**
     * @return The object storage location where to store analysis results.
     * 
     */
    public Optional<Output<ProcessorJobOutputLocationArgs>> outputLocation() {
        return Optional.ofNullable(this.outputLocation);
    }

    /**
     * How much progress the operation has made, compared to the total amount of work to be performed.
     * 
     */
    @Import(name="percentComplete")
    private @Nullable Output<Double> percentComplete;

    /**
     * @return How much progress the operation has made, compared to the total amount of work to be performed.
     * 
     */
    public Optional<Output<Double>> percentComplete() {
        return Optional.ofNullable(this.percentComplete);
    }

    /**
     * The configuration of a processor.
     * 
     */
    @Import(name="processorConfig")
    private @Nullable Output<ProcessorJobProcessorConfigArgs> processorConfig;

    /**
     * @return The configuration of a processor.
     * 
     */
    public Optional<Output<ProcessorJobProcessorConfigArgs>> processorConfig() {
        return Optional.ofNullable(this.processorConfig);
    }

    /**
     * The current state of the processor job.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return The current state of the processor job.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * The job acceptance time.
     * 
     */
    @Import(name="timeAccepted")
    private @Nullable Output<String> timeAccepted;

    /**
     * @return The job acceptance time.
     * 
     */
    public Optional<Output<String>> timeAccepted() {
        return Optional.ofNullable(this.timeAccepted);
    }

    /**
     * The job finish time.
     * 
     */
    @Import(name="timeFinished")
    private @Nullable Output<String> timeFinished;

    /**
     * @return The job finish time.
     * 
     */
    public Optional<Output<String>> timeFinished() {
        return Optional.ofNullable(this.timeFinished);
    }

    /**
     * The job start time.
     * 
     */
    @Import(name="timeStarted")
    private @Nullable Output<String> timeStarted;

    /**
     * @return The job start time.
     * 
     */
    public Optional<Output<String>> timeStarted() {
        return Optional.ofNullable(this.timeStarted);
    }

    private ProcessorJobState() {}

    private ProcessorJobState(ProcessorJobState $) {
        this.compartmentId = $.compartmentId;
        this.displayName = $.displayName;
        this.inputLocation = $.inputLocation;
        this.lifecycleDetails = $.lifecycleDetails;
        this.outputLocation = $.outputLocation;
        this.percentComplete = $.percentComplete;
        this.processorConfig = $.processorConfig;
        this.state = $.state;
        this.timeAccepted = $.timeAccepted;
        this.timeFinished = $.timeFinished;
        this.timeStarted = $.timeStarted;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ProcessorJobState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ProcessorJobState $;

        public Builder() {
            $ = new ProcessorJobState();
        }

        public Builder(ProcessorJobState defaults) {
            $ = new ProcessorJobState(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The compartment identifier.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The compartment identifier.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param displayName The display name of the processor job.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName The display name of the processor job.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param inputLocation The location of the inputs.
         * 
         * @return builder
         * 
         */
        public Builder inputLocation(@Nullable Output<ProcessorJobInputLocationArgs> inputLocation) {
            $.inputLocation = inputLocation;
            return this;
        }

        /**
         * @param inputLocation The location of the inputs.
         * 
         * @return builder
         * 
         */
        public Builder inputLocation(ProcessorJobInputLocationArgs inputLocation) {
            return inputLocation(Output.of(inputLocation));
        }

        /**
         * @param lifecycleDetails The detailed status of FAILED state.
         * 
         * @return builder
         * 
         */
        public Builder lifecycleDetails(@Nullable Output<String> lifecycleDetails) {
            $.lifecycleDetails = lifecycleDetails;
            return this;
        }

        /**
         * @param lifecycleDetails The detailed status of FAILED state.
         * 
         * @return builder
         * 
         */
        public Builder lifecycleDetails(String lifecycleDetails) {
            return lifecycleDetails(Output.of(lifecycleDetails));
        }

        /**
         * @param outputLocation The object storage location where to store analysis results.
         * 
         * @return builder
         * 
         */
        public Builder outputLocation(@Nullable Output<ProcessorJobOutputLocationArgs> outputLocation) {
            $.outputLocation = outputLocation;
            return this;
        }

        /**
         * @param outputLocation The object storage location where to store analysis results.
         * 
         * @return builder
         * 
         */
        public Builder outputLocation(ProcessorJobOutputLocationArgs outputLocation) {
            return outputLocation(Output.of(outputLocation));
        }

        /**
         * @param percentComplete How much progress the operation has made, compared to the total amount of work to be performed.
         * 
         * @return builder
         * 
         */
        public Builder percentComplete(@Nullable Output<Double> percentComplete) {
            $.percentComplete = percentComplete;
            return this;
        }

        /**
         * @param percentComplete How much progress the operation has made, compared to the total amount of work to be performed.
         * 
         * @return builder
         * 
         */
        public Builder percentComplete(Double percentComplete) {
            return percentComplete(Output.of(percentComplete));
        }

        /**
         * @param processorConfig The configuration of a processor.
         * 
         * @return builder
         * 
         */
        public Builder processorConfig(@Nullable Output<ProcessorJobProcessorConfigArgs> processorConfig) {
            $.processorConfig = processorConfig;
            return this;
        }

        /**
         * @param processorConfig The configuration of a processor.
         * 
         * @return builder
         * 
         */
        public Builder processorConfig(ProcessorJobProcessorConfigArgs processorConfig) {
            return processorConfig(Output.of(processorConfig));
        }

        /**
         * @param state The current state of the processor job.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state The current state of the processor job.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param timeAccepted The job acceptance time.
         * 
         * @return builder
         * 
         */
        public Builder timeAccepted(@Nullable Output<String> timeAccepted) {
            $.timeAccepted = timeAccepted;
            return this;
        }

        /**
         * @param timeAccepted The job acceptance time.
         * 
         * @return builder
         * 
         */
        public Builder timeAccepted(String timeAccepted) {
            return timeAccepted(Output.of(timeAccepted));
        }

        /**
         * @param timeFinished The job finish time.
         * 
         * @return builder
         * 
         */
        public Builder timeFinished(@Nullable Output<String> timeFinished) {
            $.timeFinished = timeFinished;
            return this;
        }

        /**
         * @param timeFinished The job finish time.
         * 
         * @return builder
         * 
         */
        public Builder timeFinished(String timeFinished) {
            return timeFinished(Output.of(timeFinished));
        }

        /**
         * @param timeStarted The job start time.
         * 
         * @return builder
         * 
         */
        public Builder timeStarted(@Nullable Output<String> timeStarted) {
            $.timeStarted = timeStarted;
            return this;
        }

        /**
         * @param timeStarted The job start time.
         * 
         * @return builder
         * 
         */
        public Builder timeStarted(String timeStarted) {
            return timeStarted(Output.of(timeStarted));
        }

        public ProcessorJobState build() {
            return $;
        }
    }

}
