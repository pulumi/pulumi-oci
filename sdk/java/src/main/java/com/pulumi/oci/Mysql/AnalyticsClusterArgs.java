// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Mysql;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class AnalyticsClusterArgs extends com.pulumi.resources.ResourceArgs {

    public static final AnalyticsClusterArgs Empty = new AnalyticsClusterArgs();

    /**
     * (Updatable) A change to the number of nodes in the Analytics Cluster will result in the entire cluster being torn down and re-created with the new cluster of nodes. This may result in a significant downtime for the analytics capability while the Analytics Cluster is re-provisioned.
     * 
     */
    @Import(name="clusterSize", required=true)
    private Output<Integer> clusterSize;

    /**
     * @return (Updatable) A change to the number of nodes in the Analytics Cluster will result in the entire cluster being torn down and re-created with the new cluster of nodes. This may result in a significant downtime for the analytics capability while the Analytics Cluster is re-provisioned.
     * 
     */
    public Output<Integer> clusterSize() {
        return this.clusterSize;
    }

    /**
     * The DB System [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    @Import(name="dbSystemId", required=true)
    private Output<String> dbSystemId;

    /**
     * @return The DB System [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public Output<String> dbSystemId() {
        return this.dbSystemId;
    }

    /**
     * (Updatable) A change to the shape of the nodes in the Analytics Cluster will result in the entire cluster being torn down and re-created with Compute instances of the new Shape. This may result in significant downtime for the analytics capability while the Analytics Cluster is re-provisioned.
     * 
     */
    @Import(name="shapeName", required=true)
    private Output<String> shapeName;

    /**
     * @return (Updatable) A change to the shape of the nodes in the Analytics Cluster will result in the entire cluster being torn down and re-created with Compute instances of the new Shape. This may result in significant downtime for the analytics capability while the Analytics Cluster is re-provisioned.
     * 
     */
    public Output<String> shapeName() {
        return this.shapeName;
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

    private AnalyticsClusterArgs() {}

    private AnalyticsClusterArgs(AnalyticsClusterArgs $) {
        this.clusterSize = $.clusterSize;
        this.dbSystemId = $.dbSystemId;
        this.shapeName = $.shapeName;
        this.state = $.state;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(AnalyticsClusterArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private AnalyticsClusterArgs $;

        public Builder() {
            $ = new AnalyticsClusterArgs();
        }

        public Builder(AnalyticsClusterArgs defaults) {
            $ = new AnalyticsClusterArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param clusterSize (Updatable) A change to the number of nodes in the Analytics Cluster will result in the entire cluster being torn down and re-created with the new cluster of nodes. This may result in a significant downtime for the analytics capability while the Analytics Cluster is re-provisioned.
         * 
         * @return builder
         * 
         */
        public Builder clusterSize(Output<Integer> clusterSize) {
            $.clusterSize = clusterSize;
            return this;
        }

        /**
         * @param clusterSize (Updatable) A change to the number of nodes in the Analytics Cluster will result in the entire cluster being torn down and re-created with the new cluster of nodes. This may result in a significant downtime for the analytics capability while the Analytics Cluster is re-provisioned.
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
        public Builder dbSystemId(Output<String> dbSystemId) {
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
         * @param shapeName (Updatable) A change to the shape of the nodes in the Analytics Cluster will result in the entire cluster being torn down and re-created with Compute instances of the new Shape. This may result in significant downtime for the analytics capability while the Analytics Cluster is re-provisioned.
         * 
         * @return builder
         * 
         */
        public Builder shapeName(Output<String> shapeName) {
            $.shapeName = shapeName;
            return this;
        }

        /**
         * @param shapeName (Updatable) A change to the shape of the nodes in the Analytics Cluster will result in the entire cluster being torn down and re-created with Compute instances of the new Shape. This may result in significant downtime for the analytics capability while the Analytics Cluster is re-provisioned.
         * 
         * @return builder
         * 
         */
        public Builder shapeName(String shapeName) {
            return shapeName(Output.of(shapeName));
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

        public AnalyticsClusterArgs build() {
            $.clusterSize = Objects.requireNonNull($.clusterSize, "expected parameter 'clusterSize' to be non-null");
            $.dbSystemId = Objects.requireNonNull($.dbSystemId, "expected parameter 'dbSystemId' to be non-null");
            $.shapeName = Objects.requireNonNull($.shapeName, "expected parameter 'shapeName' to be non-null");
            return $;
        }
    }

}