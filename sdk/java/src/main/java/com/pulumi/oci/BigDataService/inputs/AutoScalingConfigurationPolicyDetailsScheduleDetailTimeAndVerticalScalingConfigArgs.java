// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.BigDataService.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class AutoScalingConfigurationPolicyDetailsScheduleDetailTimeAndVerticalScalingConfigArgs extends com.pulumi.resources.ResourceArgs {

    public static final AutoScalingConfigurationPolicyDetailsScheduleDetailTimeAndVerticalScalingConfigArgs Empty = new AutoScalingConfigurationPolicyDetailsScheduleDetailTimeAndVerticalScalingConfigArgs();

    /**
     * (Updatable) For nodes with [flexible compute shapes](https://docs.cloud.oracle.com/iaas/Content/bigdata/create-cluster.htm#cluster-plan-shape), this value is the desired memory in GBs on each node. This value is not used for nodes with fixed compute shapes.
     * 
     */
    @Import(name="targetMemoryPerNode")
    private @Nullable Output<Integer> targetMemoryPerNode;

    /**
     * @return (Updatable) For nodes with [flexible compute shapes](https://docs.cloud.oracle.com/iaas/Content/bigdata/create-cluster.htm#cluster-plan-shape), this value is the desired memory in GBs on each node. This value is not used for nodes with fixed compute shapes.
     * 
     */
    public Optional<Output<Integer>> targetMemoryPerNode() {
        return Optional.ofNullable(this.targetMemoryPerNode);
    }

    /**
     * (Updatable) For nodes with [flexible compute shapes](https://docs.cloud.oracle.com/iaas/Content/bigdata/create-cluster.htm#cluster-plan-shape), this value is the desired OCPUs count on each node. This value is not used for nodes with fixed compute shapes.
     * 
     */
    @Import(name="targetOcpusPerNode")
    private @Nullable Output<Integer> targetOcpusPerNode;

    /**
     * @return (Updatable) For nodes with [flexible compute shapes](https://docs.cloud.oracle.com/iaas/Content/bigdata/create-cluster.htm#cluster-plan-shape), this value is the desired OCPUs count on each node. This value is not used for nodes with fixed compute shapes.
     * 
     */
    public Optional<Output<Integer>> targetOcpusPerNode() {
        return Optional.ofNullable(this.targetOcpusPerNode);
    }

    /**
     * (Updatable) For nodes with [fixed compute shapes](https://docs.cloud.oracle.com/iaas/Content/bigdata/create-cluster.htm#cluster-plan-shape), this value is the desired shape of each node. This value is not used for nodes with flexible compute shapes.
     * 
     */
    @Import(name="targetShape")
    private @Nullable Output<String> targetShape;

    /**
     * @return (Updatable) For nodes with [fixed compute shapes](https://docs.cloud.oracle.com/iaas/Content/bigdata/create-cluster.htm#cluster-plan-shape), this value is the desired shape of each node. This value is not used for nodes with flexible compute shapes.
     * 
     */
    public Optional<Output<String>> targetShape() {
        return Optional.ofNullable(this.targetShape);
    }

    /**
     * (Updatable) Day/time recurrence (specified following RFC 5545) at which to trigger autoscaling action. Currently only WEEKLY frequency is supported. Days of the week are specified using BYDAY field. Time of the day is specified using BYHOUR and BYMINUTE fields. Other fields are not supported.
     * 
     */
    @Import(name="timeRecurrence")
    private @Nullable Output<String> timeRecurrence;

    /**
     * @return (Updatable) Day/time recurrence (specified following RFC 5545) at which to trigger autoscaling action. Currently only WEEKLY frequency is supported. Days of the week are specified using BYDAY field. Time of the day is specified using BYHOUR and BYMINUTE fields. Other fields are not supported.
     * 
     */
    public Optional<Output<String>> timeRecurrence() {
        return Optional.ofNullable(this.timeRecurrence);
    }

    private AutoScalingConfigurationPolicyDetailsScheduleDetailTimeAndVerticalScalingConfigArgs() {}

    private AutoScalingConfigurationPolicyDetailsScheduleDetailTimeAndVerticalScalingConfigArgs(AutoScalingConfigurationPolicyDetailsScheduleDetailTimeAndVerticalScalingConfigArgs $) {
        this.targetMemoryPerNode = $.targetMemoryPerNode;
        this.targetOcpusPerNode = $.targetOcpusPerNode;
        this.targetShape = $.targetShape;
        this.timeRecurrence = $.timeRecurrence;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(AutoScalingConfigurationPolicyDetailsScheduleDetailTimeAndVerticalScalingConfigArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private AutoScalingConfigurationPolicyDetailsScheduleDetailTimeAndVerticalScalingConfigArgs $;

        public Builder() {
            $ = new AutoScalingConfigurationPolicyDetailsScheduleDetailTimeAndVerticalScalingConfigArgs();
        }

        public Builder(AutoScalingConfigurationPolicyDetailsScheduleDetailTimeAndVerticalScalingConfigArgs defaults) {
            $ = new AutoScalingConfigurationPolicyDetailsScheduleDetailTimeAndVerticalScalingConfigArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param targetMemoryPerNode (Updatable) For nodes with [flexible compute shapes](https://docs.cloud.oracle.com/iaas/Content/bigdata/create-cluster.htm#cluster-plan-shape), this value is the desired memory in GBs on each node. This value is not used for nodes with fixed compute shapes.
         * 
         * @return builder
         * 
         */
        public Builder targetMemoryPerNode(@Nullable Output<Integer> targetMemoryPerNode) {
            $.targetMemoryPerNode = targetMemoryPerNode;
            return this;
        }

        /**
         * @param targetMemoryPerNode (Updatable) For nodes with [flexible compute shapes](https://docs.cloud.oracle.com/iaas/Content/bigdata/create-cluster.htm#cluster-plan-shape), this value is the desired memory in GBs on each node. This value is not used for nodes with fixed compute shapes.
         * 
         * @return builder
         * 
         */
        public Builder targetMemoryPerNode(Integer targetMemoryPerNode) {
            return targetMemoryPerNode(Output.of(targetMemoryPerNode));
        }

        /**
         * @param targetOcpusPerNode (Updatable) For nodes with [flexible compute shapes](https://docs.cloud.oracle.com/iaas/Content/bigdata/create-cluster.htm#cluster-plan-shape), this value is the desired OCPUs count on each node. This value is not used for nodes with fixed compute shapes.
         * 
         * @return builder
         * 
         */
        public Builder targetOcpusPerNode(@Nullable Output<Integer> targetOcpusPerNode) {
            $.targetOcpusPerNode = targetOcpusPerNode;
            return this;
        }

        /**
         * @param targetOcpusPerNode (Updatable) For nodes with [flexible compute shapes](https://docs.cloud.oracle.com/iaas/Content/bigdata/create-cluster.htm#cluster-plan-shape), this value is the desired OCPUs count on each node. This value is not used for nodes with fixed compute shapes.
         * 
         * @return builder
         * 
         */
        public Builder targetOcpusPerNode(Integer targetOcpusPerNode) {
            return targetOcpusPerNode(Output.of(targetOcpusPerNode));
        }

        /**
         * @param targetShape (Updatable) For nodes with [fixed compute shapes](https://docs.cloud.oracle.com/iaas/Content/bigdata/create-cluster.htm#cluster-plan-shape), this value is the desired shape of each node. This value is not used for nodes with flexible compute shapes.
         * 
         * @return builder
         * 
         */
        public Builder targetShape(@Nullable Output<String> targetShape) {
            $.targetShape = targetShape;
            return this;
        }

        /**
         * @param targetShape (Updatable) For nodes with [fixed compute shapes](https://docs.cloud.oracle.com/iaas/Content/bigdata/create-cluster.htm#cluster-plan-shape), this value is the desired shape of each node. This value is not used for nodes with flexible compute shapes.
         * 
         * @return builder
         * 
         */
        public Builder targetShape(String targetShape) {
            return targetShape(Output.of(targetShape));
        }

        /**
         * @param timeRecurrence (Updatable) Day/time recurrence (specified following RFC 5545) at which to trigger autoscaling action. Currently only WEEKLY frequency is supported. Days of the week are specified using BYDAY field. Time of the day is specified using BYHOUR and BYMINUTE fields. Other fields are not supported.
         * 
         * @return builder
         * 
         */
        public Builder timeRecurrence(@Nullable Output<String> timeRecurrence) {
            $.timeRecurrence = timeRecurrence;
            return this;
        }

        /**
         * @param timeRecurrence (Updatable) Day/time recurrence (specified following RFC 5545) at which to trigger autoscaling action. Currently only WEEKLY frequency is supported. Days of the week are specified using BYDAY field. Time of the day is specified using BYHOUR and BYMINUTE fields. Other fields are not supported.
         * 
         * @return builder
         * 
         */
        public Builder timeRecurrence(String timeRecurrence) {
            return timeRecurrence(Output.of(timeRecurrence));
        }

        public AutoScalingConfigurationPolicyDetailsScheduleDetailTimeAndVerticalScalingConfigArgs build() {
            return $;
        }
    }

}
