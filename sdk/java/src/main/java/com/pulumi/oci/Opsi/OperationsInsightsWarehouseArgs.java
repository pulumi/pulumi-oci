// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Opsi;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Double;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class OperationsInsightsWarehouseArgs extends com.pulumi.resources.ResourceArgs {

    public static final OperationsInsightsWarehouseArgs Empty = new OperationsInsightsWarehouseArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * (Updatable) Number of OCPUs allocated to OPSI Warehouse ADW.
     * 
     */
    @Import(name="cpuAllocated", required=true)
    private Output<Double> cpuAllocated;

    /**
     * @return (Updatable) Number of OCPUs allocated to OPSI Warehouse ADW.
     * 
     */
    public Output<Double> cpuAllocated() {
        return this.cpuAllocated;
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,Object>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) User-friedly name of Operations Insights Warehouse that does not have to be unique.
     * 
     */
    @Import(name="displayName", required=true)
    private Output<String> displayName;

    /**
     * @return (Updatable) User-friedly name of Operations Insights Warehouse that does not have to be unique.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }

    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * (Updatable) Storage allocated to OPSI Warehouse ADW.
     * 
     */
    @Import(name="storageAllocatedInGbs")
    private @Nullable Output<Double> storageAllocatedInGbs;

    /**
     * @return (Updatable) Storage allocated to OPSI Warehouse ADW.
     * 
     */
    public Optional<Output<Double>> storageAllocatedInGbs() {
        return Optional.ofNullable(this.storageAllocatedInGbs);
    }

    private OperationsInsightsWarehouseArgs() {}

    private OperationsInsightsWarehouseArgs(OperationsInsightsWarehouseArgs $) {
        this.compartmentId = $.compartmentId;
        this.cpuAllocated = $.cpuAllocated;
        this.definedTags = $.definedTags;
        this.displayName = $.displayName;
        this.freeformTags = $.freeformTags;
        this.storageAllocatedInGbs = $.storageAllocatedInGbs;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(OperationsInsightsWarehouseArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private OperationsInsightsWarehouseArgs $;

        public Builder() {
            $ = new OperationsInsightsWarehouseArgs();
        }

        public Builder(OperationsInsightsWarehouseArgs defaults) {
            $ = new OperationsInsightsWarehouseArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param cpuAllocated (Updatable) Number of OCPUs allocated to OPSI Warehouse ADW.
         * 
         * @return builder
         * 
         */
        public Builder cpuAllocated(Output<Double> cpuAllocated) {
            $.cpuAllocated = cpuAllocated;
            return this;
        }

        /**
         * @param cpuAllocated (Updatable) Number of OCPUs allocated to OPSI Warehouse ADW.
         * 
         * @return builder
         * 
         */
        public Builder cpuAllocated(Double cpuAllocated) {
            return cpuAllocated(Output.of(cpuAllocated));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,Object>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,Object> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param displayName (Updatable) User-friedly name of Operations Insights Warehouse that does not have to be unique.
         * 
         * @return builder
         * 
         */
        public Builder displayName(Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) User-friedly name of Operations Insights Warehouse that does not have to be unique.
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
        public Builder freeformTags(@Nullable Output<Map<String,Object>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,Object> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param storageAllocatedInGbs (Updatable) Storage allocated to OPSI Warehouse ADW.
         * 
         * @return builder
         * 
         */
        public Builder storageAllocatedInGbs(@Nullable Output<Double> storageAllocatedInGbs) {
            $.storageAllocatedInGbs = storageAllocatedInGbs;
            return this;
        }

        /**
         * @param storageAllocatedInGbs (Updatable) Storage allocated to OPSI Warehouse ADW.
         * 
         * @return builder
         * 
         */
        public Builder storageAllocatedInGbs(Double storageAllocatedInGbs) {
            return storageAllocatedInGbs(Output.of(storageAllocatedInGbs));
        }

        public OperationsInsightsWarehouseArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            $.cpuAllocated = Objects.requireNonNull($.cpuAllocated, "expected parameter 'cpuAllocated' to be non-null");
            $.displayName = Objects.requireNonNull($.displayName, "expected parameter 'displayName' to be non-null");
            return $;
        }
    }

}