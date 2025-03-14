// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Redis.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Redis.inputs.RedisClusterNodeCollectionArgs;
import java.lang.Double;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class RedisClusterState extends com.pulumi.resources.ResourceArgs {

    public static final RedisClusterState Empty = new RedisClusterState();

    /**
     * Specifies whether the cluster is sharded or non-sharded.
     * 
     */
    @Import(name="clusterMode")
    private @Nullable Output<String> clusterMode;

    /**
     * @return Specifies whether the cluster is sharded or non-sharded.
     * 
     */
    public Optional<Output<String>> clusterMode() {
        return Optional.ofNullable(this.clusterMode);
    }

    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm#Oracle) of the compartment that contains the cluster.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm#Oracle) of the compartment that contains the cluster.
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * A message describing the current state in more detail. For example, the message might provide actionable information for a resource in `FAILED` state.
     * 
     */
    @Import(name="lifecycleDetails")
    private @Nullable Output<String> lifecycleDetails;

    /**
     * @return A message describing the current state in more detail. For example, the message might provide actionable information for a resource in `FAILED` state.
     * 
     */
    public Optional<Output<String>> lifecycleDetails() {
        return Optional.ofNullable(this.lifecycleDetails);
    }

    /**
     * The collection of  cluster nodes.
     * 
     */
    @Import(name="nodeCollections")
    private @Nullable Output<List<RedisClusterNodeCollectionArgs>> nodeCollections;

    /**
     * @return The collection of  cluster nodes.
     * 
     */
    public Optional<Output<List<RedisClusterNodeCollectionArgs>>> nodeCollections() {
        return Optional.ofNullable(this.nodeCollections);
    }

    /**
     * (Updatable) The number of nodes per shard in the cluster when clusterMode is SHARDED. This is the total number of nodes when clusterMode is NONSHARDED.
     * 
     */
    @Import(name="nodeCount")
    private @Nullable Output<Integer> nodeCount;

    /**
     * @return (Updatable) The number of nodes per shard in the cluster when clusterMode is SHARDED. This is the total number of nodes when clusterMode is NONSHARDED.
     * 
     */
    public Optional<Output<Integer>> nodeCount() {
        return Optional.ofNullable(this.nodeCount);
    }

    /**
     * (Updatable) The amount of memory allocated to the cluster&#39;s nodes, in gigabytes.
     * 
     */
    @Import(name="nodeMemoryInGbs")
    private @Nullable Output<Double> nodeMemoryInGbs;

    /**
     * @return (Updatable) The amount of memory allocated to the cluster&#39;s nodes, in gigabytes.
     * 
     */
    public Optional<Output<Double>> nodeMemoryInGbs() {
        return Optional.ofNullable(this.nodeMemoryInGbs);
    }

    /**
     * (Updatable) A list of Network Security Group (NSG) [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) associated with this cluster. For more information, see [Using an NSG for Clusters](https://docs.cloud.oracle.com/iaas/Content/ocicache/connecttocluster.htm#connecttocluster__networksecuritygroup).
     * 
     */
    @Import(name="nsgIds")
    private @Nullable Output<List<String>> nsgIds;

    /**
     * @return (Updatable) A list of Network Security Group (NSG) [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) associated with this cluster. For more information, see [Using an NSG for Clusters](https://docs.cloud.oracle.com/iaas/Content/ocicache/connecttocluster.htm#connecttocluster__networksecuritygroup).
     * 
     */
    public Optional<Output<List<String>>> nsgIds() {
        return Optional.ofNullable(this.nsgIds);
    }

    /**
     * The private IP address of the API endpoint for the cluster&#39;s primary node.
     * 
     */
    @Import(name="primaryEndpointIpAddress")
    private @Nullable Output<String> primaryEndpointIpAddress;

    /**
     * @return The private IP address of the API endpoint for the cluster&#39;s primary node.
     * 
     */
    public Optional<Output<String>> primaryEndpointIpAddress() {
        return Optional.ofNullable(this.primaryEndpointIpAddress);
    }

    /**
     * The fully qualified domain name (FQDN) of the API endpoint for the cluster&#39;s primary node.
     * 
     */
    @Import(name="primaryFqdn")
    private @Nullable Output<String> primaryFqdn;

    /**
     * @return The fully qualified domain name (FQDN) of the API endpoint for the cluster&#39;s primary node.
     * 
     */
    public Optional<Output<String>> primaryFqdn() {
        return Optional.ofNullable(this.primaryFqdn);
    }

    /**
     * The private IP address of the API endpoint for the cluster&#39;s replica nodes.
     * 
     */
    @Import(name="replicasEndpointIpAddress")
    private @Nullable Output<String> replicasEndpointIpAddress;

    /**
     * @return The private IP address of the API endpoint for the cluster&#39;s replica nodes.
     * 
     */
    public Optional<Output<String>> replicasEndpointIpAddress() {
        return Optional.ofNullable(this.replicasEndpointIpAddress);
    }

    /**
     * The fully qualified domain name (FQDN) of the API endpoint for the cluster&#39;s replica nodes.
     * 
     */
    @Import(name="replicasFqdn")
    private @Nullable Output<String> replicasFqdn;

    /**
     * @return The fully qualified domain name (FQDN) of the API endpoint for the cluster&#39;s replica nodes.
     * 
     */
    public Optional<Output<String>> replicasFqdn() {
        return Optional.ofNullable(this.replicasFqdn);
    }

    /**
     * (Updatable) The number of shards in sharded cluster. Only applicable when clusterMode is SHARDED.
     * 
     */
    @Import(name="shardCount")
    private @Nullable Output<Integer> shardCount;

    /**
     * @return (Updatable) The number of shards in sharded cluster. Only applicable when clusterMode is SHARDED.
     * 
     */
    public Optional<Output<Integer>> shardCount() {
        return Optional.ofNullable(this.shardCount);
    }

    /**
     * (Updatable) The Oracle Cloud Infrastructure Cache engine version that the cluster is running.
     * 
     */
    @Import(name="softwareVersion")
    private @Nullable Output<String> softwareVersion;

    /**
     * @return (Updatable) The Oracle Cloud Infrastructure Cache engine version that the cluster is running.
     * 
     */
    public Optional<Output<String>> softwareVersion() {
        return Optional.ofNullable(this.softwareVersion);
    }

    /**
     * The current state of the cluster.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return The current state of the cluster.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm#Oracle) of the cluster&#39;s subnet.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="subnetId")
    private @Nullable Output<String> subnetId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm#Oracle) of the cluster&#39;s subnet.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<Output<String>> subnetId() {
        return Optional.ofNullable(this.subnetId);
    }

    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    @Import(name="systemTags")
    private @Nullable Output<Map<String,String>> systemTags;

    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> systemTags() {
        return Optional.ofNullable(this.systemTags);
    }

    /**
     * The date and time the cluster was created. An [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339) formatted datetime string.
     * 
     */
    @Import(name="timeCreated")
    private @Nullable Output<String> timeCreated;

    /**
     * @return The date and time the cluster was created. An [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339) formatted datetime string.
     * 
     */
    public Optional<Output<String>> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    /**
     * The date and time the cluster was updated. An [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339) formatted datetime string.
     * 
     */
    @Import(name="timeUpdated")
    private @Nullable Output<String> timeUpdated;

    /**
     * @return The date and time the cluster was updated. An [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339) formatted datetime string.
     * 
     */
    public Optional<Output<String>> timeUpdated() {
        return Optional.ofNullable(this.timeUpdated);
    }

    private RedisClusterState() {}

    private RedisClusterState(RedisClusterState $) {
        this.clusterMode = $.clusterMode;
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.displayName = $.displayName;
        this.freeformTags = $.freeformTags;
        this.lifecycleDetails = $.lifecycleDetails;
        this.nodeCollections = $.nodeCollections;
        this.nodeCount = $.nodeCount;
        this.nodeMemoryInGbs = $.nodeMemoryInGbs;
        this.nsgIds = $.nsgIds;
        this.primaryEndpointIpAddress = $.primaryEndpointIpAddress;
        this.primaryFqdn = $.primaryFqdn;
        this.replicasEndpointIpAddress = $.replicasEndpointIpAddress;
        this.replicasFqdn = $.replicasFqdn;
        this.shardCount = $.shardCount;
        this.softwareVersion = $.softwareVersion;
        this.state = $.state;
        this.subnetId = $.subnetId;
        this.systemTags = $.systemTags;
        this.timeCreated = $.timeCreated;
        this.timeUpdated = $.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(RedisClusterState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private RedisClusterState $;

        public Builder() {
            $ = new RedisClusterState();
        }

        public Builder(RedisClusterState defaults) {
            $ = new RedisClusterState(Objects.requireNonNull(defaults));
        }

        /**
         * @param clusterMode Specifies whether the cluster is sharded or non-sharded.
         * 
         * @return builder
         * 
         */
        public Builder clusterMode(@Nullable Output<String> clusterMode) {
            $.clusterMode = clusterMode;
            return this;
        }

        /**
         * @param clusterMode Specifies whether the cluster is sharded or non-sharded.
         * 
         * @return builder
         * 
         */
        public Builder clusterMode(String clusterMode) {
            return clusterMode(Output.of(clusterMode));
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm#Oracle) of the compartment that contains the cluster.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm#Oracle) of the compartment that contains the cluster.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,String>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,String> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param displayName (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,String>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,String> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param lifecycleDetails A message describing the current state in more detail. For example, the message might provide actionable information for a resource in `FAILED` state.
         * 
         * @return builder
         * 
         */
        public Builder lifecycleDetails(@Nullable Output<String> lifecycleDetails) {
            $.lifecycleDetails = lifecycleDetails;
            return this;
        }

        /**
         * @param lifecycleDetails A message describing the current state in more detail. For example, the message might provide actionable information for a resource in `FAILED` state.
         * 
         * @return builder
         * 
         */
        public Builder lifecycleDetails(String lifecycleDetails) {
            return lifecycleDetails(Output.of(lifecycleDetails));
        }

        /**
         * @param nodeCollections The collection of  cluster nodes.
         * 
         * @return builder
         * 
         */
        public Builder nodeCollections(@Nullable Output<List<RedisClusterNodeCollectionArgs>> nodeCollections) {
            $.nodeCollections = nodeCollections;
            return this;
        }

        /**
         * @param nodeCollections The collection of  cluster nodes.
         * 
         * @return builder
         * 
         */
        public Builder nodeCollections(List<RedisClusterNodeCollectionArgs> nodeCollections) {
            return nodeCollections(Output.of(nodeCollections));
        }

        /**
         * @param nodeCollections The collection of  cluster nodes.
         * 
         * @return builder
         * 
         */
        public Builder nodeCollections(RedisClusterNodeCollectionArgs... nodeCollections) {
            return nodeCollections(List.of(nodeCollections));
        }

        /**
         * @param nodeCount (Updatable) The number of nodes per shard in the cluster when clusterMode is SHARDED. This is the total number of nodes when clusterMode is NONSHARDED.
         * 
         * @return builder
         * 
         */
        public Builder nodeCount(@Nullable Output<Integer> nodeCount) {
            $.nodeCount = nodeCount;
            return this;
        }

        /**
         * @param nodeCount (Updatable) The number of nodes per shard in the cluster when clusterMode is SHARDED. This is the total number of nodes when clusterMode is NONSHARDED.
         * 
         * @return builder
         * 
         */
        public Builder nodeCount(Integer nodeCount) {
            return nodeCount(Output.of(nodeCount));
        }

        /**
         * @param nodeMemoryInGbs (Updatable) The amount of memory allocated to the cluster&#39;s nodes, in gigabytes.
         * 
         * @return builder
         * 
         */
        public Builder nodeMemoryInGbs(@Nullable Output<Double> nodeMemoryInGbs) {
            $.nodeMemoryInGbs = nodeMemoryInGbs;
            return this;
        }

        /**
         * @param nodeMemoryInGbs (Updatable) The amount of memory allocated to the cluster&#39;s nodes, in gigabytes.
         * 
         * @return builder
         * 
         */
        public Builder nodeMemoryInGbs(Double nodeMemoryInGbs) {
            return nodeMemoryInGbs(Output.of(nodeMemoryInGbs));
        }

        /**
         * @param nsgIds (Updatable) A list of Network Security Group (NSG) [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) associated with this cluster. For more information, see [Using an NSG for Clusters](https://docs.cloud.oracle.com/iaas/Content/ocicache/connecttocluster.htm#connecttocluster__networksecuritygroup).
         * 
         * @return builder
         * 
         */
        public Builder nsgIds(@Nullable Output<List<String>> nsgIds) {
            $.nsgIds = nsgIds;
            return this;
        }

        /**
         * @param nsgIds (Updatable) A list of Network Security Group (NSG) [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) associated with this cluster. For more information, see [Using an NSG for Clusters](https://docs.cloud.oracle.com/iaas/Content/ocicache/connecttocluster.htm#connecttocluster__networksecuritygroup).
         * 
         * @return builder
         * 
         */
        public Builder nsgIds(List<String> nsgIds) {
            return nsgIds(Output.of(nsgIds));
        }

        /**
         * @param nsgIds (Updatable) A list of Network Security Group (NSG) [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) associated with this cluster. For more information, see [Using an NSG for Clusters](https://docs.cloud.oracle.com/iaas/Content/ocicache/connecttocluster.htm#connecttocluster__networksecuritygroup).
         * 
         * @return builder
         * 
         */
        public Builder nsgIds(String... nsgIds) {
            return nsgIds(List.of(nsgIds));
        }

        /**
         * @param primaryEndpointIpAddress The private IP address of the API endpoint for the cluster&#39;s primary node.
         * 
         * @return builder
         * 
         */
        public Builder primaryEndpointIpAddress(@Nullable Output<String> primaryEndpointIpAddress) {
            $.primaryEndpointIpAddress = primaryEndpointIpAddress;
            return this;
        }

        /**
         * @param primaryEndpointIpAddress The private IP address of the API endpoint for the cluster&#39;s primary node.
         * 
         * @return builder
         * 
         */
        public Builder primaryEndpointIpAddress(String primaryEndpointIpAddress) {
            return primaryEndpointIpAddress(Output.of(primaryEndpointIpAddress));
        }

        /**
         * @param primaryFqdn The fully qualified domain name (FQDN) of the API endpoint for the cluster&#39;s primary node.
         * 
         * @return builder
         * 
         */
        public Builder primaryFqdn(@Nullable Output<String> primaryFqdn) {
            $.primaryFqdn = primaryFqdn;
            return this;
        }

        /**
         * @param primaryFqdn The fully qualified domain name (FQDN) of the API endpoint for the cluster&#39;s primary node.
         * 
         * @return builder
         * 
         */
        public Builder primaryFqdn(String primaryFqdn) {
            return primaryFqdn(Output.of(primaryFqdn));
        }

        /**
         * @param replicasEndpointIpAddress The private IP address of the API endpoint for the cluster&#39;s replica nodes.
         * 
         * @return builder
         * 
         */
        public Builder replicasEndpointIpAddress(@Nullable Output<String> replicasEndpointIpAddress) {
            $.replicasEndpointIpAddress = replicasEndpointIpAddress;
            return this;
        }

        /**
         * @param replicasEndpointIpAddress The private IP address of the API endpoint for the cluster&#39;s replica nodes.
         * 
         * @return builder
         * 
         */
        public Builder replicasEndpointIpAddress(String replicasEndpointIpAddress) {
            return replicasEndpointIpAddress(Output.of(replicasEndpointIpAddress));
        }

        /**
         * @param replicasFqdn The fully qualified domain name (FQDN) of the API endpoint for the cluster&#39;s replica nodes.
         * 
         * @return builder
         * 
         */
        public Builder replicasFqdn(@Nullable Output<String> replicasFqdn) {
            $.replicasFqdn = replicasFqdn;
            return this;
        }

        /**
         * @param replicasFqdn The fully qualified domain name (FQDN) of the API endpoint for the cluster&#39;s replica nodes.
         * 
         * @return builder
         * 
         */
        public Builder replicasFqdn(String replicasFqdn) {
            return replicasFqdn(Output.of(replicasFqdn));
        }

        /**
         * @param shardCount (Updatable) The number of shards in sharded cluster. Only applicable when clusterMode is SHARDED.
         * 
         * @return builder
         * 
         */
        public Builder shardCount(@Nullable Output<Integer> shardCount) {
            $.shardCount = shardCount;
            return this;
        }

        /**
         * @param shardCount (Updatable) The number of shards in sharded cluster. Only applicable when clusterMode is SHARDED.
         * 
         * @return builder
         * 
         */
        public Builder shardCount(Integer shardCount) {
            return shardCount(Output.of(shardCount));
        }

        /**
         * @param softwareVersion (Updatable) The Oracle Cloud Infrastructure Cache engine version that the cluster is running.
         * 
         * @return builder
         * 
         */
        public Builder softwareVersion(@Nullable Output<String> softwareVersion) {
            $.softwareVersion = softwareVersion;
            return this;
        }

        /**
         * @param softwareVersion (Updatable) The Oracle Cloud Infrastructure Cache engine version that the cluster is running.
         * 
         * @return builder
         * 
         */
        public Builder softwareVersion(String softwareVersion) {
            return softwareVersion(Output.of(softwareVersion));
        }

        /**
         * @param state The current state of the cluster.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state The current state of the cluster.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param subnetId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm#Oracle) of the cluster&#39;s subnet.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder subnetId(@Nullable Output<String> subnetId) {
            $.subnetId = subnetId;
            return this;
        }

        /**
         * @param subnetId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm#Oracle) of the cluster&#39;s subnet.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder subnetId(String subnetId) {
            return subnetId(Output.of(subnetId));
        }

        /**
         * @param systemTags Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder systemTags(@Nullable Output<Map<String,String>> systemTags) {
            $.systemTags = systemTags;
            return this;
        }

        /**
         * @param systemTags Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder systemTags(Map<String,String> systemTags) {
            return systemTags(Output.of(systemTags));
        }

        /**
         * @param timeCreated The date and time the cluster was created. An [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339) formatted datetime string.
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(@Nullable Output<String> timeCreated) {
            $.timeCreated = timeCreated;
            return this;
        }

        /**
         * @param timeCreated The date and time the cluster was created. An [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339) formatted datetime string.
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(String timeCreated) {
            return timeCreated(Output.of(timeCreated));
        }

        /**
         * @param timeUpdated The date and time the cluster was updated. An [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339) formatted datetime string.
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(@Nullable Output<String> timeUpdated) {
            $.timeUpdated = timeUpdated;
            return this;
        }

        /**
         * @param timeUpdated The date and time the cluster was updated. An [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339) formatted datetime string.
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(String timeUpdated) {
            return timeUpdated(Output.of(timeUpdated));
        }

        public RedisClusterState build() {
            return $;
        }
    }

}
