// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Mysql.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Mysql.inputs.HeatWaveClusterClusterNodeArgs;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class HeatWaveClusterState extends com.pulumi.resources.ResourceArgs {

    public static final HeatWaveClusterState Empty = new HeatWaveClusterState();

    /**
     * A HeatWave node is a compute host that is part of a HeatWave cluster.
     * 
     */
    @Import(name="clusterNodes")
    private @Nullable Output<List<HeatWaveClusterClusterNodeArgs>> clusterNodes;

    /**
     * @return A HeatWave node is a compute host that is part of a HeatWave cluster.
     * 
     */
    public Optional<Output<List<HeatWaveClusterClusterNodeArgs>>> clusterNodes() {
        return Optional.ofNullable(this.clusterNodes);
    }

    /**
     * (Updatable) A change to the number of nodes in the HeatWave cluster will result in the entire cluster being torn down and re-created with the new cluster of nodes. This may result in a significant downtime for the analytics capability while the HeatWave cluster is re-provisioned.
     * 
     */
    @Import(name="clusterSize")
    private @Nullable Output<Integer> clusterSize;

    /**
     * @return (Updatable) A change to the number of nodes in the HeatWave cluster will result in the entire cluster being torn down and re-created with the new cluster of nodes. This may result in a significant downtime for the analytics capability while the HeatWave cluster is re-provisioned.
     * 
     */
    public Optional<Output<Integer>> clusterSize() {
        return Optional.ofNullable(this.clusterSize);
    }

    /**
     * The DB System [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    @Import(name="dbSystemId")
    private @Nullable Output<String> dbSystemId;

    /**
     * @return The DB System [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public Optional<Output<String>> dbSystemId() {
        return Optional.ofNullable(this.dbSystemId);
    }

    /**
     * Additional information about the current lifecycleState.
     * 
     */
    @Import(name="lifecycleDetails")
    private @Nullable Output<String> lifecycleDetails;

    /**
     * @return Additional information about the current lifecycleState.
     * 
     */
    public Optional<Output<String>> lifecycleDetails() {
        return Optional.ofNullable(this.lifecycleDetails);
    }

    /**
     * (Updatable) A change to the shape of the nodes in the HeatWave cluster will result in the entire cluster being torn down and re-created with Compute instances of the new Shape. This may result in significant downtime for the analytics capability while the HeatWave cluster is re-provisioned.
     * 
     */
    @Import(name="shapeName")
    private @Nullable Output<String> shapeName;

    /**
     * @return (Updatable) A change to the shape of the nodes in the HeatWave cluster will result in the entire cluster being torn down and re-created with Compute instances of the new Shape. This may result in significant downtime for the analytics capability while the HeatWave cluster is re-provisioned.
     * 
     */
    public Optional<Output<String>> shapeName() {
        return Optional.ofNullable(this.shapeName);
    }

    /**
     * (Updatable) The target state for the HeatWave cluster. Could be set to `ACTIVE` or `INACTIVE`.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return (Updatable) The target state for the HeatWave cluster. Could be set to `ACTIVE` or `INACTIVE`.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * The date and time the HeatWave cluster was created, as described by [RFC 3339](https://tools.ietf.org/rfc/rfc3339).
     * 
     */
    @Import(name="timeCreated")
    private @Nullable Output<String> timeCreated;

    /**
     * @return The date and time the HeatWave cluster was created, as described by [RFC 3339](https://tools.ietf.org/rfc/rfc3339).
     * 
     */
    public Optional<Output<String>> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    /**
     * The time the HeatWave cluster was last updated, as described by [RFC 3339](https://tools.ietf.org/rfc/rfc3339).
     * 
     */
    @Import(name="timeUpdated")
    private @Nullable Output<String> timeUpdated;

    /**
     * @return The time the HeatWave cluster was last updated, as described by [RFC 3339](https://tools.ietf.org/rfc/rfc3339).
     * 
     */
    public Optional<Output<String>> timeUpdated() {
        return Optional.ofNullable(this.timeUpdated);
    }

    private HeatWaveClusterState() {}

    private HeatWaveClusterState(HeatWaveClusterState $) {
        this.clusterNodes = $.clusterNodes;
        this.clusterSize = $.clusterSize;
        this.dbSystemId = $.dbSystemId;
        this.lifecycleDetails = $.lifecycleDetails;
        this.shapeName = $.shapeName;
        this.state = $.state;
        this.timeCreated = $.timeCreated;
        this.timeUpdated = $.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(HeatWaveClusterState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private HeatWaveClusterState $;

        public Builder() {
            $ = new HeatWaveClusterState();
        }

        public Builder(HeatWaveClusterState defaults) {
            $ = new HeatWaveClusterState(Objects.requireNonNull(defaults));
        }

        /**
         * @param clusterNodes A HeatWave node is a compute host that is part of a HeatWave cluster.
         * 
         * @return builder
         * 
         */
        public Builder clusterNodes(@Nullable Output<List<HeatWaveClusterClusterNodeArgs>> clusterNodes) {
            $.clusterNodes = clusterNodes;
            return this;
        }

        /**
         * @param clusterNodes A HeatWave node is a compute host that is part of a HeatWave cluster.
         * 
         * @return builder
         * 
         */
        public Builder clusterNodes(List<HeatWaveClusterClusterNodeArgs> clusterNodes) {
            return clusterNodes(Output.of(clusterNodes));
        }

        /**
         * @param clusterNodes A HeatWave node is a compute host that is part of a HeatWave cluster.
         * 
         * @return builder
         * 
         */
        public Builder clusterNodes(HeatWaveClusterClusterNodeArgs... clusterNodes) {
            return clusterNodes(List.of(clusterNodes));
        }

        /**
         * @param clusterSize (Updatable) A change to the number of nodes in the HeatWave cluster will result in the entire cluster being torn down and re-created with the new cluster of nodes. This may result in a significant downtime for the analytics capability while the HeatWave cluster is re-provisioned.
         * 
         * @return builder
         * 
         */
        public Builder clusterSize(@Nullable Output<Integer> clusterSize) {
            $.clusterSize = clusterSize;
            return this;
        }

        /**
         * @param clusterSize (Updatable) A change to the number of nodes in the HeatWave cluster will result in the entire cluster being torn down and re-created with the new cluster of nodes. This may result in a significant downtime for the analytics capability while the HeatWave cluster is re-provisioned.
         * 
         * @return builder
         * 
         */
        public Builder clusterSize(Integer clusterSize) {
            return clusterSize(Output.of(clusterSize));
        }

        /**
         * @param dbSystemId The DB System [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder dbSystemId(@Nullable Output<String> dbSystemId) {
            $.dbSystemId = dbSystemId;
            return this;
        }

        /**
         * @param dbSystemId The DB System [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder dbSystemId(String dbSystemId) {
            return dbSystemId(Output.of(dbSystemId));
        }

        /**
         * @param lifecycleDetails Additional information about the current lifecycleState.
         * 
         * @return builder
         * 
         */
        public Builder lifecycleDetails(@Nullable Output<String> lifecycleDetails) {
            $.lifecycleDetails = lifecycleDetails;
            return this;
        }

        /**
         * @param lifecycleDetails Additional information about the current lifecycleState.
         * 
         * @return builder
         * 
         */
        public Builder lifecycleDetails(String lifecycleDetails) {
            return lifecycleDetails(Output.of(lifecycleDetails));
        }

        /**
         * @param shapeName (Updatable) A change to the shape of the nodes in the HeatWave cluster will result in the entire cluster being torn down and re-created with Compute instances of the new Shape. This may result in significant downtime for the analytics capability while the HeatWave cluster is re-provisioned.
         * 
         * @return builder
         * 
         */
        public Builder shapeName(@Nullable Output<String> shapeName) {
            $.shapeName = shapeName;
            return this;
        }

        /**
         * @param shapeName (Updatable) A change to the shape of the nodes in the HeatWave cluster will result in the entire cluster being torn down and re-created with Compute instances of the new Shape. This may result in significant downtime for the analytics capability while the HeatWave cluster is re-provisioned.
         * 
         * @return builder
         * 
         */
        public Builder shapeName(String shapeName) {
            return shapeName(Output.of(shapeName));
        }

        /**
         * @param state (Updatable) The target state for the HeatWave cluster. Could be set to `ACTIVE` or `INACTIVE`.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state (Updatable) The target state for the HeatWave cluster. Could be set to `ACTIVE` or `INACTIVE`.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param timeCreated The date and time the HeatWave cluster was created, as described by [RFC 3339](https://tools.ietf.org/rfc/rfc3339).
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(@Nullable Output<String> timeCreated) {
            $.timeCreated = timeCreated;
            return this;
        }

        /**
         * @param timeCreated The date and time the HeatWave cluster was created, as described by [RFC 3339](https://tools.ietf.org/rfc/rfc3339).
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(String timeCreated) {
            return timeCreated(Output.of(timeCreated));
        }

        /**
         * @param timeUpdated The time the HeatWave cluster was last updated, as described by [RFC 3339](https://tools.ietf.org/rfc/rfc3339).
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(@Nullable Output<String> timeUpdated) {
            $.timeUpdated = timeUpdated;
            return this;
        }

        /**
         * @param timeUpdated The time the HeatWave cluster was last updated, as described by [RFC 3339](https://tools.ietf.org/rfc/rfc3339).
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(String timeUpdated) {
            return timeUpdated(Output.of(timeUpdated));
        }

        public HeatWaveClusterState build() {
            return $;
        }
    }

}