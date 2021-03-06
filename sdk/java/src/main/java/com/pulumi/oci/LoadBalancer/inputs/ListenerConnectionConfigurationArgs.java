// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LoadBalancer.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ListenerConnectionConfigurationArgs extends com.pulumi.resources.ResourceArgs {

    public static final ListenerConnectionConfigurationArgs Empty = new ListenerConnectionConfigurationArgs();

    /**
     * (Updatable) The backend TCP Proxy Protocol version.  Example: `1`
     * 
     */
    @Import(name="backendTcpProxyProtocolVersion")
    private @Nullable Output<Integer> backendTcpProxyProtocolVersion;

    /**
     * @return (Updatable) The backend TCP Proxy Protocol version.  Example: `1`
     * 
     */
    public Optional<Output<Integer>> backendTcpProxyProtocolVersion() {
        return Optional.ofNullable(this.backendTcpProxyProtocolVersion);
    }

    /**
     * (Updatable) The maximum idle time, in seconds, allowed between two successive receive or two successive send operations between the client and backend servers. A send operation does not reset the timer for receive operations. A receive operation does not reset the timer for send operations.
     * 
     */
    @Import(name="idleTimeoutInSeconds", required=true)
    private Output<String> idleTimeoutInSeconds;

    /**
     * @return (Updatable) The maximum idle time, in seconds, allowed between two successive receive or two successive send operations between the client and backend servers. A send operation does not reset the timer for receive operations. A receive operation does not reset the timer for send operations.
     * 
     */
    public Output<String> idleTimeoutInSeconds() {
        return this.idleTimeoutInSeconds;
    }

    private ListenerConnectionConfigurationArgs() {}

    private ListenerConnectionConfigurationArgs(ListenerConnectionConfigurationArgs $) {
        this.backendTcpProxyProtocolVersion = $.backendTcpProxyProtocolVersion;
        this.idleTimeoutInSeconds = $.idleTimeoutInSeconds;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ListenerConnectionConfigurationArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ListenerConnectionConfigurationArgs $;

        public Builder() {
            $ = new ListenerConnectionConfigurationArgs();
        }

        public Builder(ListenerConnectionConfigurationArgs defaults) {
            $ = new ListenerConnectionConfigurationArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param backendTcpProxyProtocolVersion (Updatable) The backend TCP Proxy Protocol version.  Example: `1`
         * 
         * @return builder
         * 
         */
        public Builder backendTcpProxyProtocolVersion(@Nullable Output<Integer> backendTcpProxyProtocolVersion) {
            $.backendTcpProxyProtocolVersion = backendTcpProxyProtocolVersion;
            return this;
        }

        /**
         * @param backendTcpProxyProtocolVersion (Updatable) The backend TCP Proxy Protocol version.  Example: `1`
         * 
         * @return builder
         * 
         */
        public Builder backendTcpProxyProtocolVersion(Integer backendTcpProxyProtocolVersion) {
            return backendTcpProxyProtocolVersion(Output.of(backendTcpProxyProtocolVersion));
        }

        /**
         * @param idleTimeoutInSeconds (Updatable) The maximum idle time, in seconds, allowed between two successive receive or two successive send operations between the client and backend servers. A send operation does not reset the timer for receive operations. A receive operation does not reset the timer for send operations.
         * 
         * @return builder
         * 
         */
        public Builder idleTimeoutInSeconds(Output<String> idleTimeoutInSeconds) {
            $.idleTimeoutInSeconds = idleTimeoutInSeconds;
            return this;
        }

        /**
         * @param idleTimeoutInSeconds (Updatable) The maximum idle time, in seconds, allowed between two successive receive or two successive send operations between the client and backend servers. A send operation does not reset the timer for receive operations. A receive operation does not reset the timer for send operations.
         * 
         * @return builder
         * 
         */
        public Builder idleTimeoutInSeconds(String idleTimeoutInSeconds) {
            return idleTimeoutInSeconds(Output.of(idleTimeoutInSeconds));
        }

        public ListenerConnectionConfigurationArgs build() {
            $.idleTimeoutInSeconds = Objects.requireNonNull($.idleTimeoutInSeconds, "expected parameter 'idleTimeoutInSeconds' to be non-null");
            return $;
        }
    }

}
