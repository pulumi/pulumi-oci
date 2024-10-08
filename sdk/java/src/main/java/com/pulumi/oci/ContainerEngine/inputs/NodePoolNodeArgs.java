// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ContainerEngine.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.ContainerEngine.inputs.NodePoolNodeErrorArgs;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class NodePoolNodeArgs extends com.pulumi.resources.ResourceArgs {

    public static final NodePoolNodeArgs Empty = new NodePoolNodeArgs();

    /**
     * The name of the availability domain in which this node is placed.
     * 
     */
    @Import(name="availabilityDomain")
    private @Nullable Output<String> availabilityDomain;

    /**
     * @return The name of the availability domain in which this node is placed.
     * 
     */
    public Optional<Output<String>> availabilityDomain() {
        return Optional.ofNullable(this.availabilityDomain);
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * An error that may be associated with the node.
     * 
     */
    @Import(name="errors")
    private @Nullable Output<List<NodePoolNodeErrorArgs>> errors;

    /**
     * @return An error that may be associated with the node.
     * 
     */
    public Optional<Output<List<NodePoolNodeErrorArgs>>> errors() {
        return Optional.ofNullable(this.errors);
    }

    /**
     * The fault domain of this node.
     * 
     */
    @Import(name="faultDomain")
    private @Nullable Output<String> faultDomain;

    /**
     * @return The fault domain of this node.
     * 
     */
    public Optional<Output<String>> faultDomain() {
        return Optional.ofNullable(this.faultDomain);
    }

    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * The OCID of the compute instance backing this node.
     * 
     */
    @Import(name="id")
    private @Nullable Output<String> id;

    /**
     * @return The OCID of the compute instance backing this node.
     * 
     */
    public Optional<Output<String>> id() {
        return Optional.ofNullable(this.id);
    }

    /**
     * (Updatable) The version of Kubernetes to install on the nodes in the node pool.
     * 
     */
    @Import(name="kubernetesVersion")
    private @Nullable Output<String> kubernetesVersion;

    /**
     * @return (Updatable) The version of Kubernetes to install on the nodes in the node pool.
     * 
     */
    public Optional<Output<String>> kubernetesVersion() {
        return Optional.ofNullable(this.kubernetesVersion);
    }

    /**
     * Details about the state of the node.
     * 
     */
    @Import(name="lifecycleDetails")
    private @Nullable Output<String> lifecycleDetails;

    /**
     * @return Details about the state of the node.
     * 
     */
    public Optional<Output<String>> lifecycleDetails() {
        return Optional.ofNullable(this.lifecycleDetails);
    }

    /**
     * (Updatable) The name of the node pool. Avoid entering confidential information.
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return (Updatable) The name of the node pool. Avoid entering confidential information.
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * The OCID of the node pool to which this node belongs.
     * 
     */
    @Import(name="nodePoolId")
    private @Nullable Output<String> nodePoolId;

    /**
     * @return The OCID of the node pool to which this node belongs.
     * 
     */
    public Optional<Output<String>> nodePoolId() {
        return Optional.ofNullable(this.nodePoolId);
    }

    /**
     * The private IP address of this node.
     * 
     */
    @Import(name="privateIp")
    private @Nullable Output<String> privateIp;

    /**
     * @return The private IP address of this node.
     * 
     */
    public Optional<Output<String>> privateIp() {
        return Optional.ofNullable(this.privateIp);
    }

    /**
     * The public IP address of this node.
     * 
     */
    @Import(name="publicIp")
    private @Nullable Output<String> publicIp;

    /**
     * @return The public IP address of this node.
     * 
     */
    public Optional<Output<String>> publicIp() {
        return Optional.ofNullable(this.publicIp);
    }

    /**
     * The state of the nodepool.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return The state of the nodepool.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * The OCID of the subnet in which this node is placed.
     * 
     */
    @Import(name="subnetId")
    private @Nullable Output<String> subnetId;

    /**
     * @return The OCID of the subnet in which this node is placed.
     * 
     */
    public Optional<Output<String>> subnetId() {
        return Optional.ofNullable(this.subnetId);
    }

    private NodePoolNodeArgs() {}

    private NodePoolNodeArgs(NodePoolNodeArgs $) {
        this.availabilityDomain = $.availabilityDomain;
        this.definedTags = $.definedTags;
        this.errors = $.errors;
        this.faultDomain = $.faultDomain;
        this.freeformTags = $.freeformTags;
        this.id = $.id;
        this.kubernetesVersion = $.kubernetesVersion;
        this.lifecycleDetails = $.lifecycleDetails;
        this.name = $.name;
        this.nodePoolId = $.nodePoolId;
        this.privateIp = $.privateIp;
        this.publicIp = $.publicIp;
        this.state = $.state;
        this.subnetId = $.subnetId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(NodePoolNodeArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private NodePoolNodeArgs $;

        public Builder() {
            $ = new NodePoolNodeArgs();
        }

        public Builder(NodePoolNodeArgs defaults) {
            $ = new NodePoolNodeArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param availabilityDomain The name of the availability domain in which this node is placed.
         * 
         * @return builder
         * 
         */
        public Builder availabilityDomain(@Nullable Output<String> availabilityDomain) {
            $.availabilityDomain = availabilityDomain;
            return this;
        }

        /**
         * @param availabilityDomain The name of the availability domain in which this node is placed.
         * 
         * @return builder
         * 
         */
        public Builder availabilityDomain(String availabilityDomain) {
            return availabilityDomain(Output.of(availabilityDomain));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,String>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,String> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param errors An error that may be associated with the node.
         * 
         * @return builder
         * 
         */
        public Builder errors(@Nullable Output<List<NodePoolNodeErrorArgs>> errors) {
            $.errors = errors;
            return this;
        }

        /**
         * @param errors An error that may be associated with the node.
         * 
         * @return builder
         * 
         */
        public Builder errors(List<NodePoolNodeErrorArgs> errors) {
            return errors(Output.of(errors));
        }

        /**
         * @param errors An error that may be associated with the node.
         * 
         * @return builder
         * 
         */
        public Builder errors(NodePoolNodeErrorArgs... errors) {
            return errors(List.of(errors));
        }

        /**
         * @param faultDomain The fault domain of this node.
         * 
         * @return builder
         * 
         */
        public Builder faultDomain(@Nullable Output<String> faultDomain) {
            $.faultDomain = faultDomain;
            return this;
        }

        /**
         * @param faultDomain The fault domain of this node.
         * 
         * @return builder
         * 
         */
        public Builder faultDomain(String faultDomain) {
            return faultDomain(Output.of(faultDomain));
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,String>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,String> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param id The OCID of the compute instance backing this node.
         * 
         * @return builder
         * 
         */
        public Builder id(@Nullable Output<String> id) {
            $.id = id;
            return this;
        }

        /**
         * @param id The OCID of the compute instance backing this node.
         * 
         * @return builder
         * 
         */
        public Builder id(String id) {
            return id(Output.of(id));
        }

        /**
         * @param kubernetesVersion (Updatable) The version of Kubernetes to install on the nodes in the node pool.
         * 
         * @return builder
         * 
         */
        public Builder kubernetesVersion(@Nullable Output<String> kubernetesVersion) {
            $.kubernetesVersion = kubernetesVersion;
            return this;
        }

        /**
         * @param kubernetesVersion (Updatable) The version of Kubernetes to install on the nodes in the node pool.
         * 
         * @return builder
         * 
         */
        public Builder kubernetesVersion(String kubernetesVersion) {
            return kubernetesVersion(Output.of(kubernetesVersion));
        }

        /**
         * @param lifecycleDetails Details about the state of the node.
         * 
         * @return builder
         * 
         */
        public Builder lifecycleDetails(@Nullable Output<String> lifecycleDetails) {
            $.lifecycleDetails = lifecycleDetails;
            return this;
        }

        /**
         * @param lifecycleDetails Details about the state of the node.
         * 
         * @return builder
         * 
         */
        public Builder lifecycleDetails(String lifecycleDetails) {
            return lifecycleDetails(Output.of(lifecycleDetails));
        }

        /**
         * @param name (Updatable) The name of the node pool. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name (Updatable) The name of the node pool. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param nodePoolId The OCID of the node pool to which this node belongs.
         * 
         * @return builder
         * 
         */
        public Builder nodePoolId(@Nullable Output<String> nodePoolId) {
            $.nodePoolId = nodePoolId;
            return this;
        }

        /**
         * @param nodePoolId The OCID of the node pool to which this node belongs.
         * 
         * @return builder
         * 
         */
        public Builder nodePoolId(String nodePoolId) {
            return nodePoolId(Output.of(nodePoolId));
        }

        /**
         * @param privateIp The private IP address of this node.
         * 
         * @return builder
         * 
         */
        public Builder privateIp(@Nullable Output<String> privateIp) {
            $.privateIp = privateIp;
            return this;
        }

        /**
         * @param privateIp The private IP address of this node.
         * 
         * @return builder
         * 
         */
        public Builder privateIp(String privateIp) {
            return privateIp(Output.of(privateIp));
        }

        /**
         * @param publicIp The public IP address of this node.
         * 
         * @return builder
         * 
         */
        public Builder publicIp(@Nullable Output<String> publicIp) {
            $.publicIp = publicIp;
            return this;
        }

        /**
         * @param publicIp The public IP address of this node.
         * 
         * @return builder
         * 
         */
        public Builder publicIp(String publicIp) {
            return publicIp(Output.of(publicIp));
        }

        /**
         * @param state The state of the nodepool.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state The state of the nodepool.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param subnetId The OCID of the subnet in which this node is placed.
         * 
         * @return builder
         * 
         */
        public Builder subnetId(@Nullable Output<String> subnetId) {
            $.subnetId = subnetId;
            return this;
        }

        /**
         * @param subnetId The OCID of the subnet in which this node is placed.
         * 
         * @return builder
         * 
         */
        public Builder subnetId(String subnetId) {
            return subnetId(Output.of(subnetId));
        }

        public NodePoolNodeArgs build() {
            return $;
        }
    }

}
