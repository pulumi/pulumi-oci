// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DevOps.inputs.DeployEnvironmentComputeInstanceGroupSelectorsArgs;
import com.pulumi.oci.DevOps.inputs.DeployEnvironmentNetworkChannelArgs;
import java.lang.String;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DeployEnvironmentArgs extends com.pulumi.resources.ResourceArgs {

    public static final DeployEnvironmentArgs Empty = new DeployEnvironmentArgs();

    /**
     * (Updatable) The OCID of the Kubernetes cluster.
     * 
     */
    @Import(name="clusterId")
    private @Nullable Output<String> clusterId;

    /**
     * @return (Updatable) The OCID of the Kubernetes cluster.
     * 
     */
    public Optional<Output<String>> clusterId() {
        return Optional.ofNullable(this.clusterId);
    }

    /**
     * (Updatable) A collection of selectors. The combination of instances matching the selectors are included in the instance group.
     * 
     */
    @Import(name="computeInstanceGroupSelectors")
    private @Nullable Output<DeployEnvironmentComputeInstanceGroupSelectorsArgs> computeInstanceGroupSelectors;

    /**
     * @return (Updatable) A collection of selectors. The combination of instances matching the selectors are included in the instance group.
     * 
     */
    public Optional<Output<DeployEnvironmentComputeInstanceGroupSelectorsArgs>> computeInstanceGroupSelectors() {
        return Optional.ofNullable(this.computeInstanceGroupSelectors);
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) Deployment environment type.
     * 
     */
    @Import(name="deployEnvironmentType", required=true)
    private Output<String> deployEnvironmentType;

    /**
     * @return (Updatable) Deployment environment type.
     * 
     */
    public Output<String> deployEnvironmentType() {
        return this.deployEnvironmentType;
    }

    /**
     * (Updatable) Optional description about the deployment environment.
     * 
     */
    @Import(name="description")
    private @Nullable Output<String> description;

    /**
     * @return (Updatable) Optional description about the deployment environment.
     * 
     */
    public Optional<Output<String>> description() {
        return Optional.ofNullable(this.description);
    }

    /**
     * (Updatable) Deployment environment display name. Avoid entering confidential information.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return (Updatable) Deployment environment display name. Avoid entering confidential information.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * (Updatable) The OCID of the Function.
     * 
     */
    @Import(name="functionId")
    private @Nullable Output<String> functionId;

    /**
     * @return (Updatable) The OCID of the Function.
     * 
     */
    public Optional<Output<String>> functionId() {
        return Optional.ofNullable(this.functionId);
    }

    /**
     * (Updatable) Specifies the configuration needed when the target Oracle Cloud Infrastructure resource, i.e., OKE cluster, resides in customer&#39;s private network.
     * 
     */
    @Import(name="networkChannel")
    private @Nullable Output<DeployEnvironmentNetworkChannelArgs> networkChannel;

    /**
     * @return (Updatable) Specifies the configuration needed when the target Oracle Cloud Infrastructure resource, i.e., OKE cluster, resides in customer&#39;s private network.
     * 
     */
    public Optional<Output<DeployEnvironmentNetworkChannelArgs>> networkChannel() {
        return Optional.ofNullable(this.networkChannel);
    }

    /**
     * The OCID of a project.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="projectId", required=true)
    private Output<String> projectId;

    /**
     * @return The OCID of a project.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> projectId() {
        return this.projectId;
    }

    private DeployEnvironmentArgs() {}

    private DeployEnvironmentArgs(DeployEnvironmentArgs $) {
        this.clusterId = $.clusterId;
        this.computeInstanceGroupSelectors = $.computeInstanceGroupSelectors;
        this.definedTags = $.definedTags;
        this.deployEnvironmentType = $.deployEnvironmentType;
        this.description = $.description;
        this.displayName = $.displayName;
        this.freeformTags = $.freeformTags;
        this.functionId = $.functionId;
        this.networkChannel = $.networkChannel;
        this.projectId = $.projectId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DeployEnvironmentArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DeployEnvironmentArgs $;

        public Builder() {
            $ = new DeployEnvironmentArgs();
        }

        public Builder(DeployEnvironmentArgs defaults) {
            $ = new DeployEnvironmentArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param clusterId (Updatable) The OCID of the Kubernetes cluster.
         * 
         * @return builder
         * 
         */
        public Builder clusterId(@Nullable Output<String> clusterId) {
            $.clusterId = clusterId;
            return this;
        }

        /**
         * @param clusterId (Updatable) The OCID of the Kubernetes cluster.
         * 
         * @return builder
         * 
         */
        public Builder clusterId(String clusterId) {
            return clusterId(Output.of(clusterId));
        }

        /**
         * @param computeInstanceGroupSelectors (Updatable) A collection of selectors. The combination of instances matching the selectors are included in the instance group.
         * 
         * @return builder
         * 
         */
        public Builder computeInstanceGroupSelectors(@Nullable Output<DeployEnvironmentComputeInstanceGroupSelectorsArgs> computeInstanceGroupSelectors) {
            $.computeInstanceGroupSelectors = computeInstanceGroupSelectors;
            return this;
        }

        /**
         * @param computeInstanceGroupSelectors (Updatable) A collection of selectors. The combination of instances matching the selectors are included in the instance group.
         * 
         * @return builder
         * 
         */
        public Builder computeInstanceGroupSelectors(DeployEnvironmentComputeInstanceGroupSelectorsArgs computeInstanceGroupSelectors) {
            return computeInstanceGroupSelectors(Output.of(computeInstanceGroupSelectors));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,String>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,String> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param deployEnvironmentType (Updatable) Deployment environment type.
         * 
         * @return builder
         * 
         */
        public Builder deployEnvironmentType(Output<String> deployEnvironmentType) {
            $.deployEnvironmentType = deployEnvironmentType;
            return this;
        }

        /**
         * @param deployEnvironmentType (Updatable) Deployment environment type.
         * 
         * @return builder
         * 
         */
        public Builder deployEnvironmentType(String deployEnvironmentType) {
            return deployEnvironmentType(Output.of(deployEnvironmentType));
        }

        /**
         * @param description (Updatable) Optional description about the deployment environment.
         * 
         * @return builder
         * 
         */
        public Builder description(@Nullable Output<String> description) {
            $.description = description;
            return this;
        }

        /**
         * @param description (Updatable) Optional description about the deployment environment.
         * 
         * @return builder
         * 
         */
        public Builder description(String description) {
            return description(Output.of(description));
        }

        /**
         * @param displayName (Updatable) Deployment environment display name. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) Deployment environment display name. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,String>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,String> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param functionId (Updatable) The OCID of the Function.
         * 
         * @return builder
         * 
         */
        public Builder functionId(@Nullable Output<String> functionId) {
            $.functionId = functionId;
            return this;
        }

        /**
         * @param functionId (Updatable) The OCID of the Function.
         * 
         * @return builder
         * 
         */
        public Builder functionId(String functionId) {
            return functionId(Output.of(functionId));
        }

        /**
         * @param networkChannel (Updatable) Specifies the configuration needed when the target Oracle Cloud Infrastructure resource, i.e., OKE cluster, resides in customer&#39;s private network.
         * 
         * @return builder
         * 
         */
        public Builder networkChannel(@Nullable Output<DeployEnvironmentNetworkChannelArgs> networkChannel) {
            $.networkChannel = networkChannel;
            return this;
        }

        /**
         * @param networkChannel (Updatable) Specifies the configuration needed when the target Oracle Cloud Infrastructure resource, i.e., OKE cluster, resides in customer&#39;s private network.
         * 
         * @return builder
         * 
         */
        public Builder networkChannel(DeployEnvironmentNetworkChannelArgs networkChannel) {
            return networkChannel(Output.of(networkChannel));
        }

        /**
         * @param projectId The OCID of a project.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder projectId(Output<String> projectId) {
            $.projectId = projectId;
            return this;
        }

        /**
         * @param projectId The OCID of a project.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder projectId(String projectId) {
            return projectId(Output.of(projectId));
        }

        public DeployEnvironmentArgs build() {
            if ($.deployEnvironmentType == null) {
                throw new MissingRequiredPropertyException("DeployEnvironmentArgs", "deployEnvironmentType");
            }
            if ($.projectId == null) {
                throw new MissingRequiredPropertyException("DeployEnvironmentArgs", "projectId");
            }
            return $;
        }
    }

}
