// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ContainerEngine.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.ContainerEngine.inputs.ClusterClusterPodNetworkOptionArgs;
import com.pulumi.oci.ContainerEngine.inputs.ClusterEndpointArgs;
import com.pulumi.oci.ContainerEngine.inputs.ClusterEndpointConfigArgs;
import com.pulumi.oci.ContainerEngine.inputs.ClusterImagePolicyConfigArgs;
import com.pulumi.oci.ContainerEngine.inputs.ClusterMetadataArgs;
import com.pulumi.oci.ContainerEngine.inputs.ClusterOptionsArgs;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ClusterState extends com.pulumi.resources.ResourceArgs {

    public static final ClusterState Empty = new ClusterState();

    /**
     * Available Kubernetes versions to which the clusters masters may be upgraded.
     * 
     */
    @Import(name="availableKubernetesUpgrades")
    private @Nullable Output<List<String>> availableKubernetesUpgrades;

    /**
     * @return Available Kubernetes versions to which the clusters masters may be upgraded.
     * 
     */
    public Optional<Output<List<String>>> availableKubernetesUpgrades() {
        return Optional.ofNullable(this.availableKubernetesUpgrades);
    }

    /**
     * Available CNIs and network options for existing and new node pools of the cluster
     * 
     */
    @Import(name="clusterPodNetworkOptions")
    private @Nullable Output<List<ClusterClusterPodNetworkOptionArgs>> clusterPodNetworkOptions;

    /**
     * @return Available CNIs and network options for existing and new node pools of the cluster
     * 
     */
    public Optional<Output<List<ClusterClusterPodNetworkOptionArgs>>> clusterPodNetworkOptions() {
        return Optional.ofNullable(this.clusterPodNetworkOptions);
    }

    /**
     * The OCID of the compartment in which to create the cluster.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return The OCID of the compartment in which to create the cluster.
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,Object>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * The network configuration for access to the Cluster control plane.
     * 
     */
    @Import(name="endpointConfig")
    private @Nullable Output<ClusterEndpointConfigArgs> endpointConfig;

    /**
     * @return The network configuration for access to the Cluster control plane.
     * 
     */
    public Optional<Output<ClusterEndpointConfigArgs>> endpointConfig() {
        return Optional.ofNullable(this.endpointConfig);
    }

    /**
     * Endpoints served up by the cluster masters.
     * 
     */
    @Import(name="endpoints")
    private @Nullable Output<List<ClusterEndpointArgs>> endpoints;

    /**
     * @return Endpoints served up by the cluster masters.
     * 
     */
    public Optional<Output<List<ClusterEndpointArgs>>> endpoints() {
        return Optional.ofNullable(this.endpoints);
    }

    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * (Updatable) The image verification policy for signature validation. Once a policy is created and enabled with one or more kms keys, the policy will ensure all images deployed has been signed with the key(s) attached to the policy.
     * 
     */
    @Import(name="imagePolicyConfig")
    private @Nullable Output<ClusterImagePolicyConfigArgs> imagePolicyConfig;

    /**
     * @return (Updatable) The image verification policy for signature validation. Once a policy is created and enabled with one or more kms keys, the policy will ensure all images deployed has been signed with the key(s) attached to the policy.
     * 
     */
    public Optional<Output<ClusterImagePolicyConfigArgs>> imagePolicyConfig() {
        return Optional.ofNullable(this.imagePolicyConfig);
    }

    /**
     * The OCID of the KMS key to be used as the master encryption key for Kubernetes secret encryption. When used, `kubernetesVersion` must be at least `v1.13.0`.
     * 
     */
    @Import(name="kmsKeyId")
    private @Nullable Output<String> kmsKeyId;

    /**
     * @return The OCID of the KMS key to be used as the master encryption key for Kubernetes secret encryption. When used, `kubernetesVersion` must be at least `v1.13.0`.
     * 
     */
    public Optional<Output<String>> kmsKeyId() {
        return Optional.ofNullable(this.kmsKeyId);
    }

    /**
     * (Updatable) The version of Kubernetes to install into the cluster masters.
     * 
     */
    @Import(name="kubernetesVersion")
    private @Nullable Output<String> kubernetesVersion;

    /**
     * @return (Updatable) The version of Kubernetes to install into the cluster masters.
     * 
     */
    public Optional<Output<String>> kubernetesVersion() {
        return Optional.ofNullable(this.kubernetesVersion);
    }

    /**
     * Details about the state of the cluster masters.
     * 
     */
    @Import(name="lifecycleDetails")
    private @Nullable Output<String> lifecycleDetails;

    /**
     * @return Details about the state of the cluster masters.
     * 
     */
    public Optional<Output<String>> lifecycleDetails() {
        return Optional.ofNullable(this.lifecycleDetails);
    }

    /**
     * Metadata about the cluster.
     * 
     */
    @Import(name="metadatas")
    private @Nullable Output<List<ClusterMetadataArgs>> metadatas;

    /**
     * @return Metadata about the cluster.
     * 
     */
    public Optional<Output<List<ClusterMetadataArgs>>> metadatas() {
        return Optional.ofNullable(this.metadatas);
    }

    /**
     * (Updatable) The name of the cluster. Avoid entering confidential information.
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return (Updatable) The name of the cluster. Avoid entering confidential information.
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * (Updatable) Optional attributes for the cluster.
     * 
     */
    @Import(name="options")
    private @Nullable Output<ClusterOptionsArgs> options;

    /**
     * @return (Updatable) Optional attributes for the cluster.
     * 
     */
    public Optional<Output<ClusterOptionsArgs>> options() {
        return Optional.ofNullable(this.options);
    }

    /**
     * The state of the cluster masters.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return The state of the cluster masters.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * The OCID of the virtual cloud network (VCN) in which to create the cluster.
     * 
     */
    @Import(name="vcnId")
    private @Nullable Output<String> vcnId;

    /**
     * @return The OCID of the virtual cloud network (VCN) in which to create the cluster.
     * 
     */
    public Optional<Output<String>> vcnId() {
        return Optional.ofNullable(this.vcnId);
    }

    private ClusterState() {}

    private ClusterState(ClusterState $) {
        this.availableKubernetesUpgrades = $.availableKubernetesUpgrades;
        this.clusterPodNetworkOptions = $.clusterPodNetworkOptions;
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.endpointConfig = $.endpointConfig;
        this.endpoints = $.endpoints;
        this.freeformTags = $.freeformTags;
        this.imagePolicyConfig = $.imagePolicyConfig;
        this.kmsKeyId = $.kmsKeyId;
        this.kubernetesVersion = $.kubernetesVersion;
        this.lifecycleDetails = $.lifecycleDetails;
        this.metadatas = $.metadatas;
        this.name = $.name;
        this.options = $.options;
        this.state = $.state;
        this.vcnId = $.vcnId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ClusterState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ClusterState $;

        public Builder() {
            $ = new ClusterState();
        }

        public Builder(ClusterState defaults) {
            $ = new ClusterState(Objects.requireNonNull(defaults));
        }

        /**
         * @param availableKubernetesUpgrades Available Kubernetes versions to which the clusters masters may be upgraded.
         * 
         * @return builder
         * 
         */
        public Builder availableKubernetesUpgrades(@Nullable Output<List<String>> availableKubernetesUpgrades) {
            $.availableKubernetesUpgrades = availableKubernetesUpgrades;
            return this;
        }

        /**
         * @param availableKubernetesUpgrades Available Kubernetes versions to which the clusters masters may be upgraded.
         * 
         * @return builder
         * 
         */
        public Builder availableKubernetesUpgrades(List<String> availableKubernetesUpgrades) {
            return availableKubernetesUpgrades(Output.of(availableKubernetesUpgrades));
        }

        /**
         * @param availableKubernetesUpgrades Available Kubernetes versions to which the clusters masters may be upgraded.
         * 
         * @return builder
         * 
         */
        public Builder availableKubernetesUpgrades(String... availableKubernetesUpgrades) {
            return availableKubernetesUpgrades(List.of(availableKubernetesUpgrades));
        }

        /**
         * @param clusterPodNetworkOptions Available CNIs and network options for existing and new node pools of the cluster
         * 
         * @return builder
         * 
         */
        public Builder clusterPodNetworkOptions(@Nullable Output<List<ClusterClusterPodNetworkOptionArgs>> clusterPodNetworkOptions) {
            $.clusterPodNetworkOptions = clusterPodNetworkOptions;
            return this;
        }

        /**
         * @param clusterPodNetworkOptions Available CNIs and network options for existing and new node pools of the cluster
         * 
         * @return builder
         * 
         */
        public Builder clusterPodNetworkOptions(List<ClusterClusterPodNetworkOptionArgs> clusterPodNetworkOptions) {
            return clusterPodNetworkOptions(Output.of(clusterPodNetworkOptions));
        }

        /**
         * @param clusterPodNetworkOptions Available CNIs and network options for existing and new node pools of the cluster
         * 
         * @return builder
         * 
         */
        public Builder clusterPodNetworkOptions(ClusterClusterPodNetworkOptionArgs... clusterPodNetworkOptions) {
            return clusterPodNetworkOptions(List.of(clusterPodNetworkOptions));
        }

        /**
         * @param compartmentId The OCID of the compartment in which to create the cluster.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The OCID of the compartment in which to create the cluster.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,Object>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,Object> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param endpointConfig The network configuration for access to the Cluster control plane.
         * 
         * @return builder
         * 
         */
        public Builder endpointConfig(@Nullable Output<ClusterEndpointConfigArgs> endpointConfig) {
            $.endpointConfig = endpointConfig;
            return this;
        }

        /**
         * @param endpointConfig The network configuration for access to the Cluster control plane.
         * 
         * @return builder
         * 
         */
        public Builder endpointConfig(ClusterEndpointConfigArgs endpointConfig) {
            return endpointConfig(Output.of(endpointConfig));
        }

        /**
         * @param endpoints Endpoints served up by the cluster masters.
         * 
         * @return builder
         * 
         */
        public Builder endpoints(@Nullable Output<List<ClusterEndpointArgs>> endpoints) {
            $.endpoints = endpoints;
            return this;
        }

        /**
         * @param endpoints Endpoints served up by the cluster masters.
         * 
         * @return builder
         * 
         */
        public Builder endpoints(List<ClusterEndpointArgs> endpoints) {
            return endpoints(Output.of(endpoints));
        }

        /**
         * @param endpoints Endpoints served up by the cluster masters.
         * 
         * @return builder
         * 
         */
        public Builder endpoints(ClusterEndpointArgs... endpoints) {
            return endpoints(List.of(endpoints));
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,Object>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,Object> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param imagePolicyConfig (Updatable) The image verification policy for signature validation. Once a policy is created and enabled with one or more kms keys, the policy will ensure all images deployed has been signed with the key(s) attached to the policy.
         * 
         * @return builder
         * 
         */
        public Builder imagePolicyConfig(@Nullable Output<ClusterImagePolicyConfigArgs> imagePolicyConfig) {
            $.imagePolicyConfig = imagePolicyConfig;
            return this;
        }

        /**
         * @param imagePolicyConfig (Updatable) The image verification policy for signature validation. Once a policy is created and enabled with one or more kms keys, the policy will ensure all images deployed has been signed with the key(s) attached to the policy.
         * 
         * @return builder
         * 
         */
        public Builder imagePolicyConfig(ClusterImagePolicyConfigArgs imagePolicyConfig) {
            return imagePolicyConfig(Output.of(imagePolicyConfig));
        }

        /**
         * @param kmsKeyId The OCID of the KMS key to be used as the master encryption key for Kubernetes secret encryption. When used, `kubernetesVersion` must be at least `v1.13.0`.
         * 
         * @return builder
         * 
         */
        public Builder kmsKeyId(@Nullable Output<String> kmsKeyId) {
            $.kmsKeyId = kmsKeyId;
            return this;
        }

        /**
         * @param kmsKeyId The OCID of the KMS key to be used as the master encryption key for Kubernetes secret encryption. When used, `kubernetesVersion` must be at least `v1.13.0`.
         * 
         * @return builder
         * 
         */
        public Builder kmsKeyId(String kmsKeyId) {
            return kmsKeyId(Output.of(kmsKeyId));
        }

        /**
         * @param kubernetesVersion (Updatable) The version of Kubernetes to install into the cluster masters.
         * 
         * @return builder
         * 
         */
        public Builder kubernetesVersion(@Nullable Output<String> kubernetesVersion) {
            $.kubernetesVersion = kubernetesVersion;
            return this;
        }

        /**
         * @param kubernetesVersion (Updatable) The version of Kubernetes to install into the cluster masters.
         * 
         * @return builder
         * 
         */
        public Builder kubernetesVersion(String kubernetesVersion) {
            return kubernetesVersion(Output.of(kubernetesVersion));
        }

        /**
         * @param lifecycleDetails Details about the state of the cluster masters.
         * 
         * @return builder
         * 
         */
        public Builder lifecycleDetails(@Nullable Output<String> lifecycleDetails) {
            $.lifecycleDetails = lifecycleDetails;
            return this;
        }

        /**
         * @param lifecycleDetails Details about the state of the cluster masters.
         * 
         * @return builder
         * 
         */
        public Builder lifecycleDetails(String lifecycleDetails) {
            return lifecycleDetails(Output.of(lifecycleDetails));
        }

        /**
         * @param metadatas Metadata about the cluster.
         * 
         * @return builder
         * 
         */
        public Builder metadatas(@Nullable Output<List<ClusterMetadataArgs>> metadatas) {
            $.metadatas = metadatas;
            return this;
        }

        /**
         * @param metadatas Metadata about the cluster.
         * 
         * @return builder
         * 
         */
        public Builder metadatas(List<ClusterMetadataArgs> metadatas) {
            return metadatas(Output.of(metadatas));
        }

        /**
         * @param metadatas Metadata about the cluster.
         * 
         * @return builder
         * 
         */
        public Builder metadatas(ClusterMetadataArgs... metadatas) {
            return metadatas(List.of(metadatas));
        }

        /**
         * @param name (Updatable) The name of the cluster. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name (Updatable) The name of the cluster. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param options (Updatable) Optional attributes for the cluster.
         * 
         * @return builder
         * 
         */
        public Builder options(@Nullable Output<ClusterOptionsArgs> options) {
            $.options = options;
            return this;
        }

        /**
         * @param options (Updatable) Optional attributes for the cluster.
         * 
         * @return builder
         * 
         */
        public Builder options(ClusterOptionsArgs options) {
            return options(Output.of(options));
        }

        /**
         * @param state The state of the cluster masters.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state The state of the cluster masters.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param vcnId The OCID of the virtual cloud network (VCN) in which to create the cluster.
         * 
         * @return builder
         * 
         */
        public Builder vcnId(@Nullable Output<String> vcnId) {
            $.vcnId = vcnId;
            return this;
        }

        /**
         * @param vcnId The OCID of the virtual cloud network (VCN) in which to create the cluster.
         * 
         * @return builder
         * 
         */
        public Builder vcnId(String vcnId) {
            return vcnId(Output.of(vcnId));
        }

        public ClusterState build() {
            return $;
        }
    }

}