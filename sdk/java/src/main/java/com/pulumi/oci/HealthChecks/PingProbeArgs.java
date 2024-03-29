// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.HealthChecks;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class PingProbeArgs extends com.pulumi.resources.ResourceArgs {

    public static final PingProbeArgs Empty = new PingProbeArgs();

    /**
     * The OCID of the compartment.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return The OCID of the compartment.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * The port on which to probe endpoints. If unspecified, probes will use the default port of their protocol.
     * 
     */
    @Import(name="port")
    private @Nullable Output<Integer> port;

    /**
     * @return The port on which to probe endpoints. If unspecified, probes will use the default port of their protocol.
     * 
     */
    public Optional<Output<Integer>> port() {
        return Optional.ofNullable(this.port);
    }

    /**
     * The protocols for ping probes.
     * 
     */
    @Import(name="protocol", required=true)
    private Output<String> protocol;

    /**
     * @return The protocols for ping probes.
     * 
     */
    public Output<String> protocol() {
        return this.protocol;
    }

    /**
     * A list of targets (hostnames or IP addresses) of the probe.
     * 
     */
    @Import(name="targets", required=true)
    private Output<List<String>> targets;

    /**
     * @return A list of targets (hostnames or IP addresses) of the probe.
     * 
     */
    public Output<List<String>> targets() {
        return this.targets;
    }

    /**
     * The probe timeout in seconds. Valid values: 10, 20, 30, and 60. The probe timeout must be less than or equal to `intervalInSeconds` for monitors.
     * 
     */
    @Import(name="timeoutInSeconds")
    private @Nullable Output<Integer> timeoutInSeconds;

    /**
     * @return The probe timeout in seconds. Valid values: 10, 20, 30, and 60. The probe timeout must be less than or equal to `intervalInSeconds` for monitors.
     * 
     */
    public Optional<Output<Integer>> timeoutInSeconds() {
        return Optional.ofNullable(this.timeoutInSeconds);
    }

    /**
     * A list of names of vantage points from which to execute the probe.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="vantagePointNames")
    private @Nullable Output<List<String>> vantagePointNames;

    /**
     * @return A list of names of vantage points from which to execute the probe.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<Output<List<String>>> vantagePointNames() {
        return Optional.ofNullable(this.vantagePointNames);
    }

    private PingProbeArgs() {}

    private PingProbeArgs(PingProbeArgs $) {
        this.compartmentId = $.compartmentId;
        this.port = $.port;
        this.protocol = $.protocol;
        this.targets = $.targets;
        this.timeoutInSeconds = $.timeoutInSeconds;
        this.vantagePointNames = $.vantagePointNames;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(PingProbeArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private PingProbeArgs $;

        public Builder() {
            $ = new PingProbeArgs();
        }

        public Builder(PingProbeArgs defaults) {
            $ = new PingProbeArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The OCID of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The OCID of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param port The port on which to probe endpoints. If unspecified, probes will use the default port of their protocol.
         * 
         * @return builder
         * 
         */
        public Builder port(@Nullable Output<Integer> port) {
            $.port = port;
            return this;
        }

        /**
         * @param port The port on which to probe endpoints. If unspecified, probes will use the default port of their protocol.
         * 
         * @return builder
         * 
         */
        public Builder port(Integer port) {
            return port(Output.of(port));
        }

        /**
         * @param protocol The protocols for ping probes.
         * 
         * @return builder
         * 
         */
        public Builder protocol(Output<String> protocol) {
            $.protocol = protocol;
            return this;
        }

        /**
         * @param protocol The protocols for ping probes.
         * 
         * @return builder
         * 
         */
        public Builder protocol(String protocol) {
            return protocol(Output.of(protocol));
        }

        /**
         * @param targets A list of targets (hostnames or IP addresses) of the probe.
         * 
         * @return builder
         * 
         */
        public Builder targets(Output<List<String>> targets) {
            $.targets = targets;
            return this;
        }

        /**
         * @param targets A list of targets (hostnames or IP addresses) of the probe.
         * 
         * @return builder
         * 
         */
        public Builder targets(List<String> targets) {
            return targets(Output.of(targets));
        }

        /**
         * @param targets A list of targets (hostnames or IP addresses) of the probe.
         * 
         * @return builder
         * 
         */
        public Builder targets(String... targets) {
            return targets(List.of(targets));
        }

        /**
         * @param timeoutInSeconds The probe timeout in seconds. Valid values: 10, 20, 30, and 60. The probe timeout must be less than or equal to `intervalInSeconds` for monitors.
         * 
         * @return builder
         * 
         */
        public Builder timeoutInSeconds(@Nullable Output<Integer> timeoutInSeconds) {
            $.timeoutInSeconds = timeoutInSeconds;
            return this;
        }

        /**
         * @param timeoutInSeconds The probe timeout in seconds. Valid values: 10, 20, 30, and 60. The probe timeout must be less than or equal to `intervalInSeconds` for monitors.
         * 
         * @return builder
         * 
         */
        public Builder timeoutInSeconds(Integer timeoutInSeconds) {
            return timeoutInSeconds(Output.of(timeoutInSeconds));
        }

        /**
         * @param vantagePointNames A list of names of vantage points from which to execute the probe.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder vantagePointNames(@Nullable Output<List<String>> vantagePointNames) {
            $.vantagePointNames = vantagePointNames;
            return this;
        }

        /**
         * @param vantagePointNames A list of names of vantage points from which to execute the probe.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder vantagePointNames(List<String> vantagePointNames) {
            return vantagePointNames(Output.of(vantagePointNames));
        }

        /**
         * @param vantagePointNames A list of names of vantage points from which to execute the probe.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder vantagePointNames(String... vantagePointNames) {
            return vantagePointNames(List.of(vantagePointNames));
        }

        public PingProbeArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("PingProbeArgs", "compartmentId");
            }
            if ($.protocol == null) {
                throw new MissingRequiredPropertyException("PingProbeArgs", "protocol");
            }
            if ($.targets == null) {
                throw new MissingRequiredPropertyException("PingProbeArgs", "targets");
            }
            return $;
        }
    }

}
