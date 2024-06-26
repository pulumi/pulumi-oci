// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ContainerEngine.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class NodePoolNodeConfigDetailsNodePoolPodNetworkOptionDetailsArgs extends com.pulumi.resources.ResourceArgs {

    public static final NodePoolNodeConfigDetailsNodePoolPodNetworkOptionDetailsArgs Empty = new NodePoolNodeConfigDetailsNodePoolPodNetworkOptionDetailsArgs();

    /**
     * (Updatable) The CNI plugin used by this node pool
     * 
     */
    @Import(name="cniType", required=true)
    private Output<String> cniType;

    /**
     * @return (Updatable) The CNI plugin used by this node pool
     * 
     */
    public Output<String> cniType() {
        return this.cniType;
    }

    /**
     * (Updatable) The max number of pods per node in the node pool. This value will be limited by the number of VNICs attachable to the node pool shape
     * 
     */
    @Import(name="maxPodsPerNode")
    private @Nullable Output<Integer> maxPodsPerNode;

    /**
     * @return (Updatable) The max number of pods per node in the node pool. This value will be limited by the number of VNICs attachable to the node pool shape
     * 
     */
    public Optional<Output<Integer>> maxPodsPerNode() {
        return Optional.ofNullable(this.maxPodsPerNode);
    }

    /**
     * (Updatable) The OCIDs of the Network Security Group(s) to associate pods for this node pool with. For more information about NSGs, see [NetworkSecurityGroup](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/20160918/NetworkSecurityGroup/).
     * 
     */
    @Import(name="podNsgIds")
    private @Nullable Output<List<String>> podNsgIds;

    /**
     * @return (Updatable) The OCIDs of the Network Security Group(s) to associate pods for this node pool with. For more information about NSGs, see [NetworkSecurityGroup](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/20160918/NetworkSecurityGroup/).
     * 
     */
    public Optional<Output<List<String>>> podNsgIds() {
        return Optional.ofNullable(this.podNsgIds);
    }

    /**
     * (Updatable) The OCIDs of the subnets in which to place pods for this node pool. This can be one of the node pool subnet IDs
     * 
     */
    @Import(name="podSubnetIds")
    private @Nullable Output<List<String>> podSubnetIds;

    /**
     * @return (Updatable) The OCIDs of the subnets in which to place pods for this node pool. This can be one of the node pool subnet IDs
     * 
     */
    public Optional<Output<List<String>>> podSubnetIds() {
        return Optional.ofNullable(this.podSubnetIds);
    }

    private NodePoolNodeConfigDetailsNodePoolPodNetworkOptionDetailsArgs() {}

    private NodePoolNodeConfigDetailsNodePoolPodNetworkOptionDetailsArgs(NodePoolNodeConfigDetailsNodePoolPodNetworkOptionDetailsArgs $) {
        this.cniType = $.cniType;
        this.maxPodsPerNode = $.maxPodsPerNode;
        this.podNsgIds = $.podNsgIds;
        this.podSubnetIds = $.podSubnetIds;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(NodePoolNodeConfigDetailsNodePoolPodNetworkOptionDetailsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private NodePoolNodeConfigDetailsNodePoolPodNetworkOptionDetailsArgs $;

        public Builder() {
            $ = new NodePoolNodeConfigDetailsNodePoolPodNetworkOptionDetailsArgs();
        }

        public Builder(NodePoolNodeConfigDetailsNodePoolPodNetworkOptionDetailsArgs defaults) {
            $ = new NodePoolNodeConfigDetailsNodePoolPodNetworkOptionDetailsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param cniType (Updatable) The CNI plugin used by this node pool
         * 
         * @return builder
         * 
         */
        public Builder cniType(Output<String> cniType) {
            $.cniType = cniType;
            return this;
        }

        /**
         * @param cniType (Updatable) The CNI plugin used by this node pool
         * 
         * @return builder
         * 
         */
        public Builder cniType(String cniType) {
            return cniType(Output.of(cniType));
        }

        /**
         * @param maxPodsPerNode (Updatable) The max number of pods per node in the node pool. This value will be limited by the number of VNICs attachable to the node pool shape
         * 
         * @return builder
         * 
         */
        public Builder maxPodsPerNode(@Nullable Output<Integer> maxPodsPerNode) {
            $.maxPodsPerNode = maxPodsPerNode;
            return this;
        }

        /**
         * @param maxPodsPerNode (Updatable) The max number of pods per node in the node pool. This value will be limited by the number of VNICs attachable to the node pool shape
         * 
         * @return builder
         * 
         */
        public Builder maxPodsPerNode(Integer maxPodsPerNode) {
            return maxPodsPerNode(Output.of(maxPodsPerNode));
        }

        /**
         * @param podNsgIds (Updatable) The OCIDs of the Network Security Group(s) to associate pods for this node pool with. For more information about NSGs, see [NetworkSecurityGroup](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/20160918/NetworkSecurityGroup/).
         * 
         * @return builder
         * 
         */
        public Builder podNsgIds(@Nullable Output<List<String>> podNsgIds) {
            $.podNsgIds = podNsgIds;
            return this;
        }

        /**
         * @param podNsgIds (Updatable) The OCIDs of the Network Security Group(s) to associate pods for this node pool with. For more information about NSGs, see [NetworkSecurityGroup](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/20160918/NetworkSecurityGroup/).
         * 
         * @return builder
         * 
         */
        public Builder podNsgIds(List<String> podNsgIds) {
            return podNsgIds(Output.of(podNsgIds));
        }

        /**
         * @param podNsgIds (Updatable) The OCIDs of the Network Security Group(s) to associate pods for this node pool with. For more information about NSGs, see [NetworkSecurityGroup](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/20160918/NetworkSecurityGroup/).
         * 
         * @return builder
         * 
         */
        public Builder podNsgIds(String... podNsgIds) {
            return podNsgIds(List.of(podNsgIds));
        }

        /**
         * @param podSubnetIds (Updatable) The OCIDs of the subnets in which to place pods for this node pool. This can be one of the node pool subnet IDs
         * 
         * @return builder
         * 
         */
        public Builder podSubnetIds(@Nullable Output<List<String>> podSubnetIds) {
            $.podSubnetIds = podSubnetIds;
            return this;
        }

        /**
         * @param podSubnetIds (Updatable) The OCIDs of the subnets in which to place pods for this node pool. This can be one of the node pool subnet IDs
         * 
         * @return builder
         * 
         */
        public Builder podSubnetIds(List<String> podSubnetIds) {
            return podSubnetIds(Output.of(podSubnetIds));
        }

        /**
         * @param podSubnetIds (Updatable) The OCIDs of the subnets in which to place pods for this node pool. This can be one of the node pool subnet IDs
         * 
         * @return builder
         * 
         */
        public Builder podSubnetIds(String... podSubnetIds) {
            return podSubnetIds(List.of(podSubnetIds));
        }

        public NodePoolNodeConfigDetailsNodePoolPodNetworkOptionDetailsArgs build() {
            if ($.cniType == null) {
                throw new MissingRequiredPropertyException("NodePoolNodeConfigDetailsNodePoolPodNetworkOptionDetailsArgs", "cniType");
            }
            return $;
        }
    }

}
