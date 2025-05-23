// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataScience.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DataScience.inputs.MlApplicationImplementationLoggingAggregatedInstanceViewLogArgs;
import com.pulumi.oci.DataScience.inputs.MlApplicationImplementationLoggingImplementationLogArgs;
import com.pulumi.oci.DataScience.inputs.MlApplicationImplementationLoggingTriggerLogArgs;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class MlApplicationImplementationLoggingArgs extends com.pulumi.resources.ResourceArgs {

    public static final MlApplicationImplementationLoggingArgs Empty = new MlApplicationImplementationLoggingArgs();

    /**
     * (Updatable) Log configuration details for particular areas of ML Application Implementation.
     * 
     */
    @Import(name="aggregatedInstanceViewLog")
    private @Nullable Output<MlApplicationImplementationLoggingAggregatedInstanceViewLogArgs> aggregatedInstanceViewLog;

    /**
     * @return (Updatable) Log configuration details for particular areas of ML Application Implementation.
     * 
     */
    public Optional<Output<MlApplicationImplementationLoggingAggregatedInstanceViewLogArgs>> aggregatedInstanceViewLog() {
        return Optional.ofNullable(this.aggregatedInstanceViewLog);
    }

    /**
     * (Updatable) Log configuration details for particular areas of ML Application Implementation.
     * 
     */
    @Import(name="implementationLog")
    private @Nullable Output<MlApplicationImplementationLoggingImplementationLogArgs> implementationLog;

    /**
     * @return (Updatable) Log configuration details for particular areas of ML Application Implementation.
     * 
     */
    public Optional<Output<MlApplicationImplementationLoggingImplementationLogArgs>> implementationLog() {
        return Optional.ofNullable(this.implementationLog);
    }

    /**
     * (Updatable) Log configuration details for particular areas of ML Application Implementation.
     * 
     */
    @Import(name="triggerLog")
    private @Nullable Output<MlApplicationImplementationLoggingTriggerLogArgs> triggerLog;

    /**
     * @return (Updatable) Log configuration details for particular areas of ML Application Implementation.
     * 
     */
    public Optional<Output<MlApplicationImplementationLoggingTriggerLogArgs>> triggerLog() {
        return Optional.ofNullable(this.triggerLog);
    }

    private MlApplicationImplementationLoggingArgs() {}

    private MlApplicationImplementationLoggingArgs(MlApplicationImplementationLoggingArgs $) {
        this.aggregatedInstanceViewLog = $.aggregatedInstanceViewLog;
        this.implementationLog = $.implementationLog;
        this.triggerLog = $.triggerLog;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(MlApplicationImplementationLoggingArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private MlApplicationImplementationLoggingArgs $;

        public Builder() {
            $ = new MlApplicationImplementationLoggingArgs();
        }

        public Builder(MlApplicationImplementationLoggingArgs defaults) {
            $ = new MlApplicationImplementationLoggingArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param aggregatedInstanceViewLog (Updatable) Log configuration details for particular areas of ML Application Implementation.
         * 
         * @return builder
         * 
         */
        public Builder aggregatedInstanceViewLog(@Nullable Output<MlApplicationImplementationLoggingAggregatedInstanceViewLogArgs> aggregatedInstanceViewLog) {
            $.aggregatedInstanceViewLog = aggregatedInstanceViewLog;
            return this;
        }

        /**
         * @param aggregatedInstanceViewLog (Updatable) Log configuration details for particular areas of ML Application Implementation.
         * 
         * @return builder
         * 
         */
        public Builder aggregatedInstanceViewLog(MlApplicationImplementationLoggingAggregatedInstanceViewLogArgs aggregatedInstanceViewLog) {
            return aggregatedInstanceViewLog(Output.of(aggregatedInstanceViewLog));
        }

        /**
         * @param implementationLog (Updatable) Log configuration details for particular areas of ML Application Implementation.
         * 
         * @return builder
         * 
         */
        public Builder implementationLog(@Nullable Output<MlApplicationImplementationLoggingImplementationLogArgs> implementationLog) {
            $.implementationLog = implementationLog;
            return this;
        }

        /**
         * @param implementationLog (Updatable) Log configuration details for particular areas of ML Application Implementation.
         * 
         * @return builder
         * 
         */
        public Builder implementationLog(MlApplicationImplementationLoggingImplementationLogArgs implementationLog) {
            return implementationLog(Output.of(implementationLog));
        }

        /**
         * @param triggerLog (Updatable) Log configuration details for particular areas of ML Application Implementation.
         * 
         * @return builder
         * 
         */
        public Builder triggerLog(@Nullable Output<MlApplicationImplementationLoggingTriggerLogArgs> triggerLog) {
            $.triggerLog = triggerLog;
            return this;
        }

        /**
         * @param triggerLog (Updatable) Log configuration details for particular areas of ML Application Implementation.
         * 
         * @return builder
         * 
         */
        public Builder triggerLog(MlApplicationImplementationLoggingTriggerLogArgs triggerLog) {
            return triggerLog(Output.of(triggerLog));
        }

        public MlApplicationImplementationLoggingArgs build() {
            return $;
        }
    }

}
