// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.DatabaseManagement.ExternalClusterArgs;
import com.pulumi.oci.DatabaseManagement.inputs.ExternalClusterState;
import com.pulumi.oci.DatabaseManagement.outputs.ExternalClusterNetworkConfiguration;
import com.pulumi.oci.DatabaseManagement.outputs.ExternalClusterScanConfiguration;
import com.pulumi.oci.DatabaseManagement.outputs.ExternalClusterVipConfiguration;
import com.pulumi.oci.Utilities;
import java.lang.Boolean;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This resource provides the External Cluster resource in Oracle Cloud Infrastructure Database Management service.
 * 
 * Updates the external cluster specified by `externalClusterId`.
 * 
 * ## Import
 * 
 * ExternalClusters can be imported using the `id`, e.g.
 * 
 * ```sh
 *  $ pulumi import oci:DatabaseManagement/externalCluster:ExternalCluster test_external_cluster &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:DatabaseManagement/externalCluster:ExternalCluster")
public class ExternalCluster extends com.pulumi.resources.CustomResource {
    /**
     * The additional details of the external cluster defined in `{&#34;key&#34;: &#34;value&#34;}` format. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Export(name="additionalDetails", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> additionalDetails;

    /**
     * @return The additional details of the external cluster defined in `{&#34;key&#34;: &#34;value&#34;}` format. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Output<Map<String,Object>> additionalDetails() {
        return this.additionalDetails;
    }
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    @Export(name="compartmentId", type=String.class, parameters={})
    private Output<String> compartmentId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * The name of the external cluster.
     * 
     */
    @Export(name="componentName", type=String.class, parameters={})
    private Output<String> componentName;

    /**
     * @return The name of the external cluster.
     * 
     */
    public Output<String> componentName() {
        return this.componentName;
    }
    /**
     * The user-friendly name for the external cluster. The name does not have to be unique.
     * 
     */
    @Export(name="displayName", type=String.class, parameters={})
    private Output<String> displayName;

    /**
     * @return The user-friendly name for the external cluster. The name does not have to be unique.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external cluster.
     * 
     */
    @Export(name="externalClusterId", type=String.class, parameters={})
    private Output<String> externalClusterId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external cluster.
     * 
     */
    public Output<String> externalClusterId() {
        return this.externalClusterId;
    }
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external connector.
     * 
     */
    @Export(name="externalConnectorId", type=String.class, parameters={})
    private Output<String> externalConnectorId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external connector.
     * 
     */
    public Output<String> externalConnectorId() {
        return this.externalConnectorId;
    }
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB system that the cluster is a part of.
     * 
     */
    @Export(name="externalDbSystemId", type=String.class, parameters={})
    private Output<String> externalDbSystemId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB system that the cluster is a part of.
     * 
     */
    public Output<String> externalDbSystemId() {
        return this.externalDbSystemId;
    }
    /**
     * The directory in which Oracle Grid Infrastructure is installed.
     * 
     */
    @Export(name="gridHome", type=String.class, parameters={})
    private Output<String> gridHome;

    /**
     * @return The directory in which Oracle Grid Infrastructure is installed.
     * 
     */
    public Output<String> gridHome() {
        return this.gridHome;
    }
    /**
     * Indicates whether the cluster is Oracle Flex Cluster or not.
     * 
     */
    @Export(name="isFlexCluster", type=Boolean.class, parameters={})
    private Output<Boolean> isFlexCluster;

    /**
     * @return Indicates whether the cluster is Oracle Flex Cluster or not.
     * 
     */
    public Output<Boolean> isFlexCluster() {
        return this.isFlexCluster;
    }
    /**
     * Additional information about the current lifecycle state.
     * 
     */
    @Export(name="lifecycleDetails", type=String.class, parameters={})
    private Output<String> lifecycleDetails;

    /**
     * @return Additional information about the current lifecycle state.
     * 
     */
    public Output<String> lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * The list of network address configurations of the external cluster.
     * 
     */
    @Export(name="networkConfigurations", type=List.class, parameters={ExternalClusterNetworkConfiguration.class})
    private Output<List<ExternalClusterNetworkConfiguration>> networkConfigurations;

    /**
     * @return The list of network address configurations of the external cluster.
     * 
     */
    public Output<List<ExternalClusterNetworkConfiguration>> networkConfigurations() {
        return this.networkConfigurations;
    }
    /**
     * The location of the Oracle Cluster Registry (OCR).
     * 
     */
    @Export(name="ocrFileLocation", type=String.class, parameters={})
    private Output<String> ocrFileLocation;

    /**
     * @return The location of the Oracle Cluster Registry (OCR).
     * 
     */
    public Output<String> ocrFileLocation() {
        return this.ocrFileLocation;
    }
    /**
     * The list of Single Client Access Name (SCAN) configurations of the external cluster.
     * 
     */
    @Export(name="scanConfigurations", type=List.class, parameters={ExternalClusterScanConfiguration.class})
    private Output<List<ExternalClusterScanConfiguration>> scanConfigurations;

    /**
     * @return The list of Single Client Access Name (SCAN) configurations of the external cluster.
     * 
     */
    public Output<List<ExternalClusterScanConfiguration>> scanConfigurations() {
        return this.scanConfigurations;
    }
    /**
     * The current lifecycle state of the external cluster.
     * 
     */
    @Export(name="state", type=String.class, parameters={})
    private Output<String> state;

    /**
     * @return The current lifecycle state of the external cluster.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * The date and time the external cluster was created.
     * 
     */
    @Export(name="timeCreated", type=String.class, parameters={})
    private Output<String> timeCreated;

    /**
     * @return The date and time the external cluster was created.
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * The date and time the external cluster was last updated.
     * 
     */
    @Export(name="timeUpdated", type=String.class, parameters={})
    private Output<String> timeUpdated;

    /**
     * @return The date and time the external cluster was last updated.
     * 
     */
    public Output<String> timeUpdated() {
        return this.timeUpdated;
    }
    /**
     * The cluster version.
     * 
     */
    @Export(name="version", type=String.class, parameters={})
    private Output<String> version;

    /**
     * @return The cluster version.
     * 
     */
    public Output<String> version() {
        return this.version;
    }
    /**
     * The list of Virtual IP (VIP) configurations of the external cluster.
     * 
     */
    @Export(name="vipConfigurations", type=List.class, parameters={ExternalClusterVipConfiguration.class})
    private Output<List<ExternalClusterVipConfiguration>> vipConfigurations;

    /**
     * @return The list of Virtual IP (VIP) configurations of the external cluster.
     * 
     */
    public Output<List<ExternalClusterVipConfiguration>> vipConfigurations() {
        return this.vipConfigurations;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public ExternalCluster(String name) {
        this(name, ExternalClusterArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public ExternalCluster(String name, ExternalClusterArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public ExternalCluster(String name, ExternalClusterArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:DatabaseManagement/externalCluster:ExternalCluster", name, args == null ? ExternalClusterArgs.Empty : args, makeResourceOptions(options, Codegen.empty()));
    }

    private ExternalCluster(String name, Output<String> id, @Nullable ExternalClusterState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:DatabaseManagement/externalCluster:ExternalCluster", name, state, makeResourceOptions(options, id));
    }

    private static com.pulumi.resources.CustomResourceOptions makeResourceOptions(@Nullable com.pulumi.resources.CustomResourceOptions options, @Nullable Output<String> id) {
        var defaultOptions = com.pulumi.resources.CustomResourceOptions.builder()
            .version(Utilities.getVersion())
            .build();
        return com.pulumi.resources.CustomResourceOptions.merge(defaultOptions, options, id);
    }

    /**
     * Get an existing Host resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state
     * @param options Optional settings to control the behavior of the CustomResource.
     */
    public static ExternalCluster get(String name, Output<String> id, @Nullable ExternalClusterState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new ExternalCluster(name, id, state, options);
    }
}