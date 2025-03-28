// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ComputeGpuMemoryClusterArgs extends com.pulumi.resources.ResourceArgs {

    public static final ComputeGpuMemoryClusterArgs Empty = new ComputeGpuMemoryClusterArgs();

    /**
     * The availability domain of the GPU memory cluster.
     * 
     */
    @Import(name="availabilityDomain", required=true)
    private Output<String> availabilityDomain;

    /**
     * @return The availability domain of the GPU memory cluster.
     * 
     */
    public Output<String> availabilityDomain() {
        return this.availabilityDomain;
    }

    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the compute GPU memory cluster. compartment.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the compute GPU memory cluster. compartment.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compute cluster.
     * 
     */
    @Import(name="computeClusterId", required=true)
    private Output<String> computeClusterId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compute cluster.
     * 
     */
    public Output<String> computeClusterId() {
        return this.computeClusterId;
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
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
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the GPU memory fabric.
     * 
     */
    @Import(name="gpuMemoryFabricId")
    private @Nullable Output<String> gpuMemoryFabricId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the GPU memory fabric.
     * 
     */
    public Optional<Output<String>> gpuMemoryFabricId() {
        return Optional.ofNullable(this.gpuMemoryFabricId);
    }

    /**
     * (Updatable) Instance Configuration to be used for this GPU Memory Cluster
     * 
     */
    @Import(name="instanceConfigurationId", required=true)
    private Output<String> instanceConfigurationId;

    /**
     * @return (Updatable) Instance Configuration to be used for this GPU Memory Cluster
     * 
     */
    public Output<String> instanceConfigurationId() {
        return this.instanceConfigurationId;
    }

    /**
     * (Updatable) The number of instances currently running in the GpuMemoryCluster
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="size")
    private @Nullable Output<String> size;

    /**
     * @return (Updatable) The number of instances currently running in the GpuMemoryCluster
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<Output<String>> size() {
        return Optional.ofNullable(this.size);
    }

    private ComputeGpuMemoryClusterArgs() {}

    private ComputeGpuMemoryClusterArgs(ComputeGpuMemoryClusterArgs $) {
        this.availabilityDomain = $.availabilityDomain;
        this.compartmentId = $.compartmentId;
        this.computeClusterId = $.computeClusterId;
        this.definedTags = $.definedTags;
        this.displayName = $.displayName;
        this.freeformTags = $.freeformTags;
        this.gpuMemoryFabricId = $.gpuMemoryFabricId;
        this.instanceConfigurationId = $.instanceConfigurationId;
        this.size = $.size;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ComputeGpuMemoryClusterArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ComputeGpuMemoryClusterArgs $;

        public Builder() {
            $ = new ComputeGpuMemoryClusterArgs();
        }

        public Builder(ComputeGpuMemoryClusterArgs defaults) {
            $ = new ComputeGpuMemoryClusterArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param availabilityDomain The availability domain of the GPU memory cluster.
         * 
         * @return builder
         * 
         */
        public Builder availabilityDomain(Output<String> availabilityDomain) {
            $.availabilityDomain = availabilityDomain;
            return this;
        }

        /**
         * @param availabilityDomain The availability domain of the GPU memory cluster.
         * 
         * @return builder
         * 
         */
        public Builder availabilityDomain(String availabilityDomain) {
            return availabilityDomain(Output.of(availabilityDomain));
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the compute GPU memory cluster. compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the compute GPU memory cluster. compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param computeClusterId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compute cluster.
         * 
         * @return builder
         * 
         */
        public Builder computeClusterId(Output<String> computeClusterId) {
            $.computeClusterId = computeClusterId;
            return this;
        }

        /**
         * @param computeClusterId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compute cluster.
         * 
         * @return builder
         * 
         */
        public Builder computeClusterId(String computeClusterId) {
            return computeClusterId(Output.of(computeClusterId));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,String>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
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
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,String>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,String> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param gpuMemoryFabricId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the GPU memory fabric.
         * 
         * @return builder
         * 
         */
        public Builder gpuMemoryFabricId(@Nullable Output<String> gpuMemoryFabricId) {
            $.gpuMemoryFabricId = gpuMemoryFabricId;
            return this;
        }

        /**
         * @param gpuMemoryFabricId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the GPU memory fabric.
         * 
         * @return builder
         * 
         */
        public Builder gpuMemoryFabricId(String gpuMemoryFabricId) {
            return gpuMemoryFabricId(Output.of(gpuMemoryFabricId));
        }

        /**
         * @param instanceConfigurationId (Updatable) Instance Configuration to be used for this GPU Memory Cluster
         * 
         * @return builder
         * 
         */
        public Builder instanceConfigurationId(Output<String> instanceConfigurationId) {
            $.instanceConfigurationId = instanceConfigurationId;
            return this;
        }

        /**
         * @param instanceConfigurationId (Updatable) Instance Configuration to be used for this GPU Memory Cluster
         * 
         * @return builder
         * 
         */
        public Builder instanceConfigurationId(String instanceConfigurationId) {
            return instanceConfigurationId(Output.of(instanceConfigurationId));
        }

        /**
         * @param size (Updatable) The number of instances currently running in the GpuMemoryCluster
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder size(@Nullable Output<String> size) {
            $.size = size;
            return this;
        }

        /**
         * @param size (Updatable) The number of instances currently running in the GpuMemoryCluster
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder size(String size) {
            return size(Output.of(size));
        }

        public ComputeGpuMemoryClusterArgs build() {
            if ($.availabilityDomain == null) {
                throw new MissingRequiredPropertyException("ComputeGpuMemoryClusterArgs", "availabilityDomain");
            }
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("ComputeGpuMemoryClusterArgs", "compartmentId");
            }
            if ($.computeClusterId == null) {
                throw new MissingRequiredPropertyException("ComputeGpuMemoryClusterArgs", "computeClusterId");
            }
            if ($.instanceConfigurationId == null) {
                throw new MissingRequiredPropertyException("ComputeGpuMemoryClusterArgs", "instanceConfigurationId");
            }
            return $;
        }
    }

}
