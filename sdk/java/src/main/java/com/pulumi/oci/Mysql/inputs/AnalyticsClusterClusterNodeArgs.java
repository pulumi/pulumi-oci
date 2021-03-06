// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Mysql.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class AnalyticsClusterClusterNodeArgs extends com.pulumi.resources.ResourceArgs {

    public static final AnalyticsClusterClusterNodeArgs Empty = new AnalyticsClusterClusterNodeArgs();

    /**
     * The ID of the node within MySQL Analytics Cluster.
     * 
     */
    @Import(name="nodeId")
    private @Nullable Output<String> nodeId;

    /**
     * @return The ID of the node within MySQL Analytics Cluster.
     * 
     */
    public Optional<Output<String>> nodeId() {
        return Optional.ofNullable(this.nodeId);
    }

    /**
     * (Updatable) The target state for the Analytics Cluster. Could be set to `ACTIVE` or `INACTIVE`.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return (Updatable) The target state for the Analytics Cluster. Could be set to `ACTIVE` or `INACTIVE`.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * The date and time the Analytics Cluster was created, as described by [RFC 3339](https://tools.ietf.org/rfc/rfc3339).
     * 
     */
    @Import(name="timeCreated")
    private @Nullable Output<String> timeCreated;

    /**
     * @return The date and time the Analytics Cluster was created, as described by [RFC 3339](https://tools.ietf.org/rfc/rfc3339).
     * 
     */
    public Optional<Output<String>> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    /**
     * The time the Analytics Cluster was last updated, as described by [RFC 3339](https://tools.ietf.org/rfc/rfc3339).
     * 
     */
    @Import(name="timeUpdated")
    private @Nullable Output<String> timeUpdated;

    /**
     * @return The time the Analytics Cluster was last updated, as described by [RFC 3339](https://tools.ietf.org/rfc/rfc3339).
     * 
     */
    public Optional<Output<String>> timeUpdated() {
        return Optional.ofNullable(this.timeUpdated);
    }

    private AnalyticsClusterClusterNodeArgs() {}

    private AnalyticsClusterClusterNodeArgs(AnalyticsClusterClusterNodeArgs $) {
        this.nodeId = $.nodeId;
        this.state = $.state;
        this.timeCreated = $.timeCreated;
        this.timeUpdated = $.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(AnalyticsClusterClusterNodeArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private AnalyticsClusterClusterNodeArgs $;

        public Builder() {
            $ = new AnalyticsClusterClusterNodeArgs();
        }

        public Builder(AnalyticsClusterClusterNodeArgs defaults) {
            $ = new AnalyticsClusterClusterNodeArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param nodeId The ID of the node within MySQL Analytics Cluster.
         * 
         * @return builder
         * 
         */
        public Builder nodeId(@Nullable Output<String> nodeId) {
            $.nodeId = nodeId;
            return this;
        }

        /**
         * @param nodeId The ID of the node within MySQL Analytics Cluster.
         * 
         * @return builder
         * 
         */
        public Builder nodeId(String nodeId) {
            return nodeId(Output.of(nodeId));
        }

        /**
         * @param state (Updatable) The target state for the Analytics Cluster. Could be set to `ACTIVE` or `INACTIVE`.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state (Updatable) The target state for the Analytics Cluster. Could be set to `ACTIVE` or `INACTIVE`.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param timeCreated The date and time the Analytics Cluster was created, as described by [RFC 3339](https://tools.ietf.org/rfc/rfc3339).
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(@Nullable Output<String> timeCreated) {
            $.timeCreated = timeCreated;
            return this;
        }

        /**
         * @param timeCreated The date and time the Analytics Cluster was created, as described by [RFC 3339](https://tools.ietf.org/rfc/rfc3339).
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(String timeCreated) {
            return timeCreated(Output.of(timeCreated));
        }

        /**
         * @param timeUpdated The time the Analytics Cluster was last updated, as described by [RFC 3339](https://tools.ietf.org/rfc/rfc3339).
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(@Nullable Output<String> timeUpdated) {
            $.timeUpdated = timeUpdated;
            return this;
        }

        /**
         * @param timeUpdated The time the Analytics Cluster was last updated, as described by [RFC 3339](https://tools.ietf.org/rfc/rfc3339).
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(String timeUpdated) {
            return timeUpdated(Output.of(timeUpdated));
        }

        public AnalyticsClusterClusterNodeArgs build() {
            return $;
        }
    }

}
