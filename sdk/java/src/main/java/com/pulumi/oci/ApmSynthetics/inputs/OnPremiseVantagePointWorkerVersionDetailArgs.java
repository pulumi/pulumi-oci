// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApmSynthetics.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class OnPremiseVantagePointWorkerVersionDetailArgs extends com.pulumi.resources.ResourceArgs {

    public static final OnPremiseVantagePointWorkerVersionDetailArgs Empty = new OnPremiseVantagePointWorkerVersionDetailArgs();

    /**
     * Latest image version of the On-premise VP worker.
     * 
     */
    @Import(name="latestVersion")
    private @Nullable Output<String> latestVersion;

    /**
     * @return Latest image version of the On-premise VP worker.
     * 
     */
    public Optional<Output<String>> latestVersion() {
        return Optional.ofNullable(this.latestVersion);
    }

    /**
     * Minimum supported image version of the On-premise VP worker.
     * 
     */
    @Import(name="minSupportedVersion")
    private @Nullable Output<String> minSupportedVersion;

    /**
     * @return Minimum supported image version of the On-premise VP worker.
     * 
     */
    public Optional<Output<String>> minSupportedVersion() {
        return Optional.ofNullable(this.minSupportedVersion);
    }

    /**
     * Image version of the On-premise VP worker.
     * 
     */
    @Import(name="version")
    private @Nullable Output<String> version;

    /**
     * @return Image version of the On-premise VP worker.
     * 
     */
    public Optional<Output<String>> version() {
        return Optional.ofNullable(this.version);
    }

    private OnPremiseVantagePointWorkerVersionDetailArgs() {}

    private OnPremiseVantagePointWorkerVersionDetailArgs(OnPremiseVantagePointWorkerVersionDetailArgs $) {
        this.latestVersion = $.latestVersion;
        this.minSupportedVersion = $.minSupportedVersion;
        this.version = $.version;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(OnPremiseVantagePointWorkerVersionDetailArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private OnPremiseVantagePointWorkerVersionDetailArgs $;

        public Builder() {
            $ = new OnPremiseVantagePointWorkerVersionDetailArgs();
        }

        public Builder(OnPremiseVantagePointWorkerVersionDetailArgs defaults) {
            $ = new OnPremiseVantagePointWorkerVersionDetailArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param latestVersion Latest image version of the On-premise VP worker.
         * 
         * @return builder
         * 
         */
        public Builder latestVersion(@Nullable Output<String> latestVersion) {
            $.latestVersion = latestVersion;
            return this;
        }

        /**
         * @param latestVersion Latest image version of the On-premise VP worker.
         * 
         * @return builder
         * 
         */
        public Builder latestVersion(String latestVersion) {
            return latestVersion(Output.of(latestVersion));
        }

        /**
         * @param minSupportedVersion Minimum supported image version of the On-premise VP worker.
         * 
         * @return builder
         * 
         */
        public Builder minSupportedVersion(@Nullable Output<String> minSupportedVersion) {
            $.minSupportedVersion = minSupportedVersion;
            return this;
        }

        /**
         * @param minSupportedVersion Minimum supported image version of the On-premise VP worker.
         * 
         * @return builder
         * 
         */
        public Builder minSupportedVersion(String minSupportedVersion) {
            return minSupportedVersion(Output.of(minSupportedVersion));
        }

        /**
         * @param version Image version of the On-premise VP worker.
         * 
         * @return builder
         * 
         */
        public Builder version(@Nullable Output<String> version) {
            $.version = version;
            return this;
        }

        /**
         * @param version Image version of the On-premise VP worker.
         * 
         * @return builder
         * 
         */
        public Builder version(String version) {
            return version(Output.of(version));
        }

        public OnPremiseVantagePointWorkerVersionDetailArgs build() {
            return $;
        }
    }

}
