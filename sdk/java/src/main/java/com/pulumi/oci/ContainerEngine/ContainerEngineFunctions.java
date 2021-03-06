// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ContainerEngine;

import com.pulumi.core.Output;
import com.pulumi.core.TypeShape;
import com.pulumi.deployment.Deployment;
import com.pulumi.deployment.InvokeOptions;
import com.pulumi.oci.ContainerEngine.inputs.GetClusterKubeConfigArgs;
import com.pulumi.oci.ContainerEngine.inputs.GetClusterKubeConfigPlainArgs;
import com.pulumi.oci.ContainerEngine.inputs.GetClusterOptionArgs;
import com.pulumi.oci.ContainerEngine.inputs.GetClusterOptionPlainArgs;
import com.pulumi.oci.ContainerEngine.inputs.GetClustersArgs;
import com.pulumi.oci.ContainerEngine.inputs.GetClustersPlainArgs;
import com.pulumi.oci.ContainerEngine.inputs.GetMigrateToNativeVcnStatusArgs;
import com.pulumi.oci.ContainerEngine.inputs.GetMigrateToNativeVcnStatusPlainArgs;
import com.pulumi.oci.ContainerEngine.inputs.GetNodePoolArgs;
import com.pulumi.oci.ContainerEngine.inputs.GetNodePoolOptionArgs;
import com.pulumi.oci.ContainerEngine.inputs.GetNodePoolOptionPlainArgs;
import com.pulumi.oci.ContainerEngine.inputs.GetNodePoolPlainArgs;
import com.pulumi.oci.ContainerEngine.inputs.GetNodePoolsArgs;
import com.pulumi.oci.ContainerEngine.inputs.GetNodePoolsPlainArgs;
import com.pulumi.oci.ContainerEngine.inputs.GetWorkRequestErrorsArgs;
import com.pulumi.oci.ContainerEngine.inputs.GetWorkRequestErrorsPlainArgs;
import com.pulumi.oci.ContainerEngine.inputs.GetWorkRequestLogEntriesArgs;
import com.pulumi.oci.ContainerEngine.inputs.GetWorkRequestLogEntriesPlainArgs;
import com.pulumi.oci.ContainerEngine.inputs.GetWorkRequestsArgs;
import com.pulumi.oci.ContainerEngine.inputs.GetWorkRequestsPlainArgs;
import com.pulumi.oci.ContainerEngine.outputs.GetClusterKubeConfigResult;
import com.pulumi.oci.ContainerEngine.outputs.GetClusterOptionResult;
import com.pulumi.oci.ContainerEngine.outputs.GetClustersResult;
import com.pulumi.oci.ContainerEngine.outputs.GetMigrateToNativeVcnStatusResult;
import com.pulumi.oci.ContainerEngine.outputs.GetNodePoolOptionResult;
import com.pulumi.oci.ContainerEngine.outputs.GetNodePoolResult;
import com.pulumi.oci.ContainerEngine.outputs.GetNodePoolsResult;
import com.pulumi.oci.ContainerEngine.outputs.GetWorkRequestErrorsResult;
import com.pulumi.oci.ContainerEngine.outputs.GetWorkRequestLogEntriesResult;
import com.pulumi.oci.ContainerEngine.outputs.GetWorkRequestsResult;
import com.pulumi.oci.Utilities;
import java.util.concurrent.CompletableFuture;

public final class ContainerEngineFunctions {
    /**
     * This data source provides details about a specific Cluster Kube Config resource in Oracle Cloud Infrastructure Container Engine service.
     * 
     * Create the Kubeconfig YAML for a cluster.
     * 
     * ## Example Usage
     * 
     */
    public static Output<GetClusterKubeConfigResult> getClusterKubeConfig(GetClusterKubeConfigArgs args) {
        return getClusterKubeConfig(args, InvokeOptions.Empty);
    }
    /**
     * This data source provides details about a specific Cluster Kube Config resource in Oracle Cloud Infrastructure Container Engine service.
     * 
     * Create the Kubeconfig YAML for a cluster.
     * 
     * ## Example Usage
     * 
     */
    public static CompletableFuture<GetClusterKubeConfigResult> getClusterKubeConfigPlain(GetClusterKubeConfigPlainArgs args) {
        return getClusterKubeConfigPlain(args, InvokeOptions.Empty);
    }
    /**
     * This data source provides details about a specific Cluster Kube Config resource in Oracle Cloud Infrastructure Container Engine service.
     * 
     * Create the Kubeconfig YAML for a cluster.
     * 
     * ## Example Usage
     * 
     */
    public static Output<GetClusterKubeConfigResult> getClusterKubeConfig(GetClusterKubeConfigArgs args, InvokeOptions options) {
        return Deployment.getInstance().invoke("oci:ContainerEngine/getClusterKubeConfig:getClusterKubeConfig", TypeShape.of(GetClusterKubeConfigResult.class), args, Utilities.withVersion(options));
    }
    /**
     * This data source provides details about a specific Cluster Kube Config resource in Oracle Cloud Infrastructure Container Engine service.
     * 
     * Create the Kubeconfig YAML for a cluster.
     * 
     * ## Example Usage
     * 
     */
    public static CompletableFuture<GetClusterKubeConfigResult> getClusterKubeConfigPlain(GetClusterKubeConfigPlainArgs args, InvokeOptions options) {
        return Deployment.getInstance().invokeAsync("oci:ContainerEngine/getClusterKubeConfig:getClusterKubeConfig", TypeShape.of(GetClusterKubeConfigResult.class), args, Utilities.withVersion(options));
    }
    /**
     * This data source provides details about a specific Cluster Option resource in Oracle Cloud Infrastructure Container Engine service.
     * 
     * Get options available for clusters.
     * 
     * ## Example Usage
     * 
     */
    public static Output<GetClusterOptionResult> getClusterOption(GetClusterOptionArgs args) {
        return getClusterOption(args, InvokeOptions.Empty);
    }
    /**
     * This data source provides details about a specific Cluster Option resource in Oracle Cloud Infrastructure Container Engine service.
     * 
     * Get options available for clusters.
     * 
     * ## Example Usage
     * 
     */
    public static CompletableFuture<GetClusterOptionResult> getClusterOptionPlain(GetClusterOptionPlainArgs args) {
        return getClusterOptionPlain(args, InvokeOptions.Empty);
    }
    /**
     * This data source provides details about a specific Cluster Option resource in Oracle Cloud Infrastructure Container Engine service.
     * 
     * Get options available for clusters.
     * 
     * ## Example Usage
     * 
     */
    public static Output<GetClusterOptionResult> getClusterOption(GetClusterOptionArgs args, InvokeOptions options) {
        return Deployment.getInstance().invoke("oci:ContainerEngine/getClusterOption:getClusterOption", TypeShape.of(GetClusterOptionResult.class), args, Utilities.withVersion(options));
    }
    /**
     * This data source provides details about a specific Cluster Option resource in Oracle Cloud Infrastructure Container Engine service.
     * 
     * Get options available for clusters.
     * 
     * ## Example Usage
     * 
     */
    public static CompletableFuture<GetClusterOptionResult> getClusterOptionPlain(GetClusterOptionPlainArgs args, InvokeOptions options) {
        return Deployment.getInstance().invokeAsync("oci:ContainerEngine/getClusterOption:getClusterOption", TypeShape.of(GetClusterOptionResult.class), args, Utilities.withVersion(options));
    }
    /**
     * This data source provides the list of Clusters in Oracle Cloud Infrastructure Container Engine service.
     * 
     * List all the cluster objects in a compartment.
     * 
     * ## Example Usage
     * 
     */
    public static Output<GetClustersResult> getClusters(GetClustersArgs args) {
        return getClusters(args, InvokeOptions.Empty);
    }
    /**
     * This data source provides the list of Clusters in Oracle Cloud Infrastructure Container Engine service.
     * 
     * List all the cluster objects in a compartment.
     * 
     * ## Example Usage
     * 
     */
    public static CompletableFuture<GetClustersResult> getClustersPlain(GetClustersPlainArgs args) {
        return getClustersPlain(args, InvokeOptions.Empty);
    }
    /**
     * This data source provides the list of Clusters in Oracle Cloud Infrastructure Container Engine service.
     * 
     * List all the cluster objects in a compartment.
     * 
     * ## Example Usage
     * 
     */
    public static Output<GetClustersResult> getClusters(GetClustersArgs args, InvokeOptions options) {
        return Deployment.getInstance().invoke("oci:ContainerEngine/getClusters:getClusters", TypeShape.of(GetClustersResult.class), args, Utilities.withVersion(options));
    }
    /**
     * This data source provides the list of Clusters in Oracle Cloud Infrastructure Container Engine service.
     * 
     * List all the cluster objects in a compartment.
     * 
     * ## Example Usage
     * 
     */
    public static CompletableFuture<GetClustersResult> getClustersPlain(GetClustersPlainArgs args, InvokeOptions options) {
        return Deployment.getInstance().invokeAsync("oci:ContainerEngine/getClusters:getClusters", TypeShape.of(GetClustersResult.class), args, Utilities.withVersion(options));
    }
    public static Output<GetMigrateToNativeVcnStatusResult> getMigrateToNativeVcnStatus(GetMigrateToNativeVcnStatusArgs args) {
        return getMigrateToNativeVcnStatus(args, InvokeOptions.Empty);
    }
    public static CompletableFuture<GetMigrateToNativeVcnStatusResult> getMigrateToNativeVcnStatusPlain(GetMigrateToNativeVcnStatusPlainArgs args) {
        return getMigrateToNativeVcnStatusPlain(args, InvokeOptions.Empty);
    }
    public static Output<GetMigrateToNativeVcnStatusResult> getMigrateToNativeVcnStatus(GetMigrateToNativeVcnStatusArgs args, InvokeOptions options) {
        return Deployment.getInstance().invoke("oci:ContainerEngine/getMigrateToNativeVcnStatus:getMigrateToNativeVcnStatus", TypeShape.of(GetMigrateToNativeVcnStatusResult.class), args, Utilities.withVersion(options));
    }
    public static CompletableFuture<GetMigrateToNativeVcnStatusResult> getMigrateToNativeVcnStatusPlain(GetMigrateToNativeVcnStatusPlainArgs args, InvokeOptions options) {
        return Deployment.getInstance().invokeAsync("oci:ContainerEngine/getMigrateToNativeVcnStatus:getMigrateToNativeVcnStatus", TypeShape.of(GetMigrateToNativeVcnStatusResult.class), args, Utilities.withVersion(options));
    }
    /**
     * This data source provides details about a specific Node Pool resource in Oracle Cloud Infrastructure Container Engine service.
     * 
     * Get the details of a node pool.
     * 
     * ## Example Usage
     * 
     */
    public static Output<GetNodePoolResult> getNodePool(GetNodePoolArgs args) {
        return getNodePool(args, InvokeOptions.Empty);
    }
    /**
     * This data source provides details about a specific Node Pool resource in Oracle Cloud Infrastructure Container Engine service.
     * 
     * Get the details of a node pool.
     * 
     * ## Example Usage
     * 
     */
    public static CompletableFuture<GetNodePoolResult> getNodePoolPlain(GetNodePoolPlainArgs args) {
        return getNodePoolPlain(args, InvokeOptions.Empty);
    }
    /**
     * This data source provides details about a specific Node Pool resource in Oracle Cloud Infrastructure Container Engine service.
     * 
     * Get the details of a node pool.
     * 
     * ## Example Usage
     * 
     */
    public static Output<GetNodePoolResult> getNodePool(GetNodePoolArgs args, InvokeOptions options) {
        return Deployment.getInstance().invoke("oci:ContainerEngine/getNodePool:getNodePool", TypeShape.of(GetNodePoolResult.class), args, Utilities.withVersion(options));
    }
    /**
     * This data source provides details about a specific Node Pool resource in Oracle Cloud Infrastructure Container Engine service.
     * 
     * Get the details of a node pool.
     * 
     * ## Example Usage
     * 
     */
    public static CompletableFuture<GetNodePoolResult> getNodePoolPlain(GetNodePoolPlainArgs args, InvokeOptions options) {
        return Deployment.getInstance().invokeAsync("oci:ContainerEngine/getNodePool:getNodePool", TypeShape.of(GetNodePoolResult.class), args, Utilities.withVersion(options));
    }
    /**
     * This data source provides details about a specific Node Pool Option resource in Oracle Cloud Infrastructure Container Engine service.
     * 
     * Get options available for node pools.
     * 
     * ## Example Usage
     * 
     */
    public static Output<GetNodePoolOptionResult> getNodePoolOption(GetNodePoolOptionArgs args) {
        return getNodePoolOption(args, InvokeOptions.Empty);
    }
    /**
     * This data source provides details about a specific Node Pool Option resource in Oracle Cloud Infrastructure Container Engine service.
     * 
     * Get options available for node pools.
     * 
     * ## Example Usage
     * 
     */
    public static CompletableFuture<GetNodePoolOptionResult> getNodePoolOptionPlain(GetNodePoolOptionPlainArgs args) {
        return getNodePoolOptionPlain(args, InvokeOptions.Empty);
    }
    /**
     * This data source provides details about a specific Node Pool Option resource in Oracle Cloud Infrastructure Container Engine service.
     * 
     * Get options available for node pools.
     * 
     * ## Example Usage
     * 
     */
    public static Output<GetNodePoolOptionResult> getNodePoolOption(GetNodePoolOptionArgs args, InvokeOptions options) {
        return Deployment.getInstance().invoke("oci:ContainerEngine/getNodePoolOption:getNodePoolOption", TypeShape.of(GetNodePoolOptionResult.class), args, Utilities.withVersion(options));
    }
    /**
     * This data source provides details about a specific Node Pool Option resource in Oracle Cloud Infrastructure Container Engine service.
     * 
     * Get options available for node pools.
     * 
     * ## Example Usage
     * 
     */
    public static CompletableFuture<GetNodePoolOptionResult> getNodePoolOptionPlain(GetNodePoolOptionPlainArgs args, InvokeOptions options) {
        return Deployment.getInstance().invokeAsync("oci:ContainerEngine/getNodePoolOption:getNodePoolOption", TypeShape.of(GetNodePoolOptionResult.class), args, Utilities.withVersion(options));
    }
    /**
     * This data source provides the list of Node Pools in Oracle Cloud Infrastructure Container Engine service.
     * 
     * List all the node pools in a compartment, and optionally filter by cluster.
     * 
     * ## Example Usage
     * 
     */
    public static Output<GetNodePoolsResult> getNodePools(GetNodePoolsArgs args) {
        return getNodePools(args, InvokeOptions.Empty);
    }
    /**
     * This data source provides the list of Node Pools in Oracle Cloud Infrastructure Container Engine service.
     * 
     * List all the node pools in a compartment, and optionally filter by cluster.
     * 
     * ## Example Usage
     * 
     */
    public static CompletableFuture<GetNodePoolsResult> getNodePoolsPlain(GetNodePoolsPlainArgs args) {
        return getNodePoolsPlain(args, InvokeOptions.Empty);
    }
    /**
     * This data source provides the list of Node Pools in Oracle Cloud Infrastructure Container Engine service.
     * 
     * List all the node pools in a compartment, and optionally filter by cluster.
     * 
     * ## Example Usage
     * 
     */
    public static Output<GetNodePoolsResult> getNodePools(GetNodePoolsArgs args, InvokeOptions options) {
        return Deployment.getInstance().invoke("oci:ContainerEngine/getNodePools:getNodePools", TypeShape.of(GetNodePoolsResult.class), args, Utilities.withVersion(options));
    }
    /**
     * This data source provides the list of Node Pools in Oracle Cloud Infrastructure Container Engine service.
     * 
     * List all the node pools in a compartment, and optionally filter by cluster.
     * 
     * ## Example Usage
     * 
     */
    public static CompletableFuture<GetNodePoolsResult> getNodePoolsPlain(GetNodePoolsPlainArgs args, InvokeOptions options) {
        return Deployment.getInstance().invokeAsync("oci:ContainerEngine/getNodePools:getNodePools", TypeShape.of(GetNodePoolsResult.class), args, Utilities.withVersion(options));
    }
    /**
     * This data source provides the list of Work Request Errors in Oracle Cloud Infrastructure Container Engine service.
     * 
     * Get the errors of a work request.
     * 
     * ## Example Usage
     * 
     */
    public static Output<GetWorkRequestErrorsResult> getWorkRequestErrors(GetWorkRequestErrorsArgs args) {
        return getWorkRequestErrors(args, InvokeOptions.Empty);
    }
    /**
     * This data source provides the list of Work Request Errors in Oracle Cloud Infrastructure Container Engine service.
     * 
     * Get the errors of a work request.
     * 
     * ## Example Usage
     * 
     */
    public static CompletableFuture<GetWorkRequestErrorsResult> getWorkRequestErrorsPlain(GetWorkRequestErrorsPlainArgs args) {
        return getWorkRequestErrorsPlain(args, InvokeOptions.Empty);
    }
    /**
     * This data source provides the list of Work Request Errors in Oracle Cloud Infrastructure Container Engine service.
     * 
     * Get the errors of a work request.
     * 
     * ## Example Usage
     * 
     */
    public static Output<GetWorkRequestErrorsResult> getWorkRequestErrors(GetWorkRequestErrorsArgs args, InvokeOptions options) {
        return Deployment.getInstance().invoke("oci:ContainerEngine/getWorkRequestErrors:getWorkRequestErrors", TypeShape.of(GetWorkRequestErrorsResult.class), args, Utilities.withVersion(options));
    }
    /**
     * This data source provides the list of Work Request Errors in Oracle Cloud Infrastructure Container Engine service.
     * 
     * Get the errors of a work request.
     * 
     * ## Example Usage
     * 
     */
    public static CompletableFuture<GetWorkRequestErrorsResult> getWorkRequestErrorsPlain(GetWorkRequestErrorsPlainArgs args, InvokeOptions options) {
        return Deployment.getInstance().invokeAsync("oci:ContainerEngine/getWorkRequestErrors:getWorkRequestErrors", TypeShape.of(GetWorkRequestErrorsResult.class), args, Utilities.withVersion(options));
    }
    /**
     * This data source provides the list of Work Request Log Entries in Oracle Cloud Infrastructure Container Engine service.
     * 
     * Get the logs of a work request.
     * 
     * ## Example Usage
     * 
     */
    public static Output<GetWorkRequestLogEntriesResult> getWorkRequestLogEntries(GetWorkRequestLogEntriesArgs args) {
        return getWorkRequestLogEntries(args, InvokeOptions.Empty);
    }
    /**
     * This data source provides the list of Work Request Log Entries in Oracle Cloud Infrastructure Container Engine service.
     * 
     * Get the logs of a work request.
     * 
     * ## Example Usage
     * 
     */
    public static CompletableFuture<GetWorkRequestLogEntriesResult> getWorkRequestLogEntriesPlain(GetWorkRequestLogEntriesPlainArgs args) {
        return getWorkRequestLogEntriesPlain(args, InvokeOptions.Empty);
    }
    /**
     * This data source provides the list of Work Request Log Entries in Oracle Cloud Infrastructure Container Engine service.
     * 
     * Get the logs of a work request.
     * 
     * ## Example Usage
     * 
     */
    public static Output<GetWorkRequestLogEntriesResult> getWorkRequestLogEntries(GetWorkRequestLogEntriesArgs args, InvokeOptions options) {
        return Deployment.getInstance().invoke("oci:ContainerEngine/getWorkRequestLogEntries:getWorkRequestLogEntries", TypeShape.of(GetWorkRequestLogEntriesResult.class), args, Utilities.withVersion(options));
    }
    /**
     * This data source provides the list of Work Request Log Entries in Oracle Cloud Infrastructure Container Engine service.
     * 
     * Get the logs of a work request.
     * 
     * ## Example Usage
     * 
     */
    public static CompletableFuture<GetWorkRequestLogEntriesResult> getWorkRequestLogEntriesPlain(GetWorkRequestLogEntriesPlainArgs args, InvokeOptions options) {
        return Deployment.getInstance().invokeAsync("oci:ContainerEngine/getWorkRequestLogEntries:getWorkRequestLogEntries", TypeShape.of(GetWorkRequestLogEntriesResult.class), args, Utilities.withVersion(options));
    }
    /**
     * This data source provides the list of Work Requests in Oracle Cloud Infrastructure Container Engine service.
     * 
     * List all work requests in a compartment.
     * 
     * ## Example Usage
     * 
     */
    public static Output<GetWorkRequestsResult> getWorkRequests(GetWorkRequestsArgs args) {
        return getWorkRequests(args, InvokeOptions.Empty);
    }
    /**
     * This data source provides the list of Work Requests in Oracle Cloud Infrastructure Container Engine service.
     * 
     * List all work requests in a compartment.
     * 
     * ## Example Usage
     * 
     */
    public static CompletableFuture<GetWorkRequestsResult> getWorkRequestsPlain(GetWorkRequestsPlainArgs args) {
        return getWorkRequestsPlain(args, InvokeOptions.Empty);
    }
    /**
     * This data source provides the list of Work Requests in Oracle Cloud Infrastructure Container Engine service.
     * 
     * List all work requests in a compartment.
     * 
     * ## Example Usage
     * 
     */
    public static Output<GetWorkRequestsResult> getWorkRequests(GetWorkRequestsArgs args, InvokeOptions options) {
        return Deployment.getInstance().invoke("oci:ContainerEngine/getWorkRequests:getWorkRequests", TypeShape.of(GetWorkRequestsResult.class), args, Utilities.withVersion(options));
    }
    /**
     * This data source provides the list of Work Requests in Oracle Cloud Infrastructure Container Engine service.
     * 
     * List all work requests in a compartment.
     * 
     * ## Example Usage
     * 
     */
    public static CompletableFuture<GetWorkRequestsResult> getWorkRequestsPlain(GetWorkRequestsPlainArgs args, InvokeOptions options) {
        return Deployment.getInstance().invokeAsync("oci:ContainerEngine/getWorkRequests:getWorkRequests", TypeShape.of(GetWorkRequestsResult.class), args, Utilities.withVersion(options));
    }
}
