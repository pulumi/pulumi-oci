// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Opensearch.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ClusterOutboundClusterConfigOutboundClusterArgs extends com.pulumi.resources.ResourceArgs {

    public static final ClusterOutboundClusterConfigOutboundClusterArgs Empty = new ClusterOutboundClusterConfigOutboundClusterArgs();

    /**
     * (Updatable) Name of the Outbound cluster. Avoid entering confidential information.
     * 
     */
    @Import(name="displayName", required=true)
    private Output<String> displayName;

    /**
     * @return (Updatable) Name of the Outbound cluster. Avoid entering confidential information.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }

    /**
     * (Updatable) Flag to indicate whether to skip the Outbound cluster during cross cluster search, if it is unavailable
     * 
     */
    @Import(name="isSkipUnavailable")
    private @Nullable Output<Boolean> isSkipUnavailable;

    /**
     * @return (Updatable) Flag to indicate whether to skip the Outbound cluster during cross cluster search, if it is unavailable
     * 
     */
    public Optional<Output<Boolean>> isSkipUnavailable() {
        return Optional.ofNullable(this.isSkipUnavailable);
    }

    /**
     * (Updatable) Mode for the cross cluster connection
     * 
     */
    @Import(name="mode")
    private @Nullable Output<String> mode;

    /**
     * @return (Updatable) Mode for the cross cluster connection
     * 
     */
    public Optional<Output<String>> mode() {
        return Optional.ofNullable(this.mode);
    }

    /**
     * (Updatable) Sets the time interval between regular application-level ping messages that are sent to try and keep outbound cluster connections alive. If set to -1, application-level ping messages to this outbound cluster are not sent. If unset, application-level ping messages are sent according to the global transport.ping_schedule setting, which defaults to -1 meaning that pings are not sent.
     * 
     */
    @Import(name="pingSchedule")
    private @Nullable Output<String> pingSchedule;

    /**
     * @return (Updatable) Sets the time interval between regular application-level ping messages that are sent to try and keep outbound cluster connections alive. If set to -1, application-level ping messages to this outbound cluster are not sent. If unset, application-level ping messages are sent according to the global transport.ping_schedule setting, which defaults to -1 meaning that pings are not sent.
     * 
     */
    public Optional<Output<String>> pingSchedule() {
        return Optional.ofNullable(this.pingSchedule);
    }

    /**
     * (Updatable) OCID of the Outbound cluster
     * 
     */
    @Import(name="seedClusterId", required=true)
    private Output<String> seedClusterId;

    /**
     * @return (Updatable) OCID of the Outbound cluster
     * 
     */
    public Output<String> seedClusterId() {
        return this.seedClusterId;
    }

    private ClusterOutboundClusterConfigOutboundClusterArgs() {}

    private ClusterOutboundClusterConfigOutboundClusterArgs(ClusterOutboundClusterConfigOutboundClusterArgs $) {
        this.displayName = $.displayName;
        this.isSkipUnavailable = $.isSkipUnavailable;
        this.mode = $.mode;
        this.pingSchedule = $.pingSchedule;
        this.seedClusterId = $.seedClusterId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ClusterOutboundClusterConfigOutboundClusterArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ClusterOutboundClusterConfigOutboundClusterArgs $;

        public Builder() {
            $ = new ClusterOutboundClusterConfigOutboundClusterArgs();
        }

        public Builder(ClusterOutboundClusterConfigOutboundClusterArgs defaults) {
            $ = new ClusterOutboundClusterConfigOutboundClusterArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param displayName (Updatable) Name of the Outbound cluster. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) Name of the Outbound cluster. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param isSkipUnavailable (Updatable) Flag to indicate whether to skip the Outbound cluster during cross cluster search, if it is unavailable
         * 
         * @return builder
         * 
         */
        public Builder isSkipUnavailable(@Nullable Output<Boolean> isSkipUnavailable) {
            $.isSkipUnavailable = isSkipUnavailable;
            return this;
        }

        /**
         * @param isSkipUnavailable (Updatable) Flag to indicate whether to skip the Outbound cluster during cross cluster search, if it is unavailable
         * 
         * @return builder
         * 
         */
        public Builder isSkipUnavailable(Boolean isSkipUnavailable) {
            return isSkipUnavailable(Output.of(isSkipUnavailable));
        }

        /**
         * @param mode (Updatable) Mode for the cross cluster connection
         * 
         * @return builder
         * 
         */
        public Builder mode(@Nullable Output<String> mode) {
            $.mode = mode;
            return this;
        }

        /**
         * @param mode (Updatable) Mode for the cross cluster connection
         * 
         * @return builder
         * 
         */
        public Builder mode(String mode) {
            return mode(Output.of(mode));
        }

        /**
         * @param pingSchedule (Updatable) Sets the time interval between regular application-level ping messages that are sent to try and keep outbound cluster connections alive. If set to -1, application-level ping messages to this outbound cluster are not sent. If unset, application-level ping messages are sent according to the global transport.ping_schedule setting, which defaults to -1 meaning that pings are not sent.
         * 
         * @return builder
         * 
         */
        public Builder pingSchedule(@Nullable Output<String> pingSchedule) {
            $.pingSchedule = pingSchedule;
            return this;
        }

        /**
         * @param pingSchedule (Updatable) Sets the time interval between regular application-level ping messages that are sent to try and keep outbound cluster connections alive. If set to -1, application-level ping messages to this outbound cluster are not sent. If unset, application-level ping messages are sent according to the global transport.ping_schedule setting, which defaults to -1 meaning that pings are not sent.
         * 
         * @return builder
         * 
         */
        public Builder pingSchedule(String pingSchedule) {
            return pingSchedule(Output.of(pingSchedule));
        }

        /**
         * @param seedClusterId (Updatable) OCID of the Outbound cluster
         * 
         * @return builder
         * 
         */
        public Builder seedClusterId(Output<String> seedClusterId) {
            $.seedClusterId = seedClusterId;
            return this;
        }

        /**
         * @param seedClusterId (Updatable) OCID of the Outbound cluster
         * 
         * @return builder
         * 
         */
        public Builder seedClusterId(String seedClusterId) {
            return seedClusterId(Output.of(seedClusterId));
        }

        public ClusterOutboundClusterConfigOutboundClusterArgs build() {
            if ($.displayName == null) {
                throw new MissingRequiredPropertyException("ClusterOutboundClusterConfigOutboundClusterArgs", "displayName");
            }
            if ($.seedClusterId == null) {
                throw new MissingRequiredPropertyException("ClusterOutboundClusterConfigOutboundClusterArgs", "seedClusterId");
            }
            return $;
        }
    }

}
