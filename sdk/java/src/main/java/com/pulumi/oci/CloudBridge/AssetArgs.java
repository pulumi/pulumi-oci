// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudBridge;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.CloudBridge.inputs.AssetComputeArgs;
import com.pulumi.oci.CloudBridge.inputs.AssetVmArgs;
import com.pulumi.oci.CloudBridge.inputs.AssetVmwareVcenterArgs;
import com.pulumi.oci.CloudBridge.inputs.AssetVmwareVmArgs;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class AssetArgs extends com.pulumi.resources.ResourceArgs {

    public static final AssetArgs Empty = new AssetArgs();

    /**
     * (Updatable) List of asset source OCID.
     * 
     */
    @Import(name="assetSourceIds")
    private @Nullable Output<List<String>> assetSourceIds;

    /**
     * @return (Updatable) List of asset source OCID.
     * 
     */
    public Optional<Output<List<String>>> assetSourceIds() {
        return Optional.ofNullable(this.assetSourceIds);
    }

    /**
     * (Updatable) The type of asset.
     * 
     */
    @Import(name="assetType", required=true)
    private Output<String> assetType;

    /**
     * @return (Updatable) The type of asset.
     * 
     */
    public Output<String> assetType() {
        return this.assetType;
    }

    /**
     * (Updatable) The OCID of the compartment that the asset belongs to.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The OCID of the compartment that the asset belongs to.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * (Updatable) Compute related properties.
     * 
     */
    @Import(name="compute")
    private @Nullable Output<AssetComputeArgs> compute;

    /**
     * @return (Updatable) Compute related properties.
     * 
     */
    public Optional<Output<AssetComputeArgs>> compute() {
        return Optional.ofNullable(this.compute);
    }

    /**
     * (Updatable) The defined tags associated with this resource, if any. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,Object>> definedTags;

    /**
     * @return (Updatable) The defined tags associated with this resource, if any. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) Asset display name.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return (Updatable) Asset display name.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * The key of the asset from the external environment.
     * 
     */
    @Import(name="externalAssetKey", required=true)
    private Output<String> externalAssetKey;

    /**
     * @return The key of the asset from the external environment.
     * 
     */
    public Output<String> externalAssetKey() {
        return this.externalAssetKey;
    }

    /**
     * (Updatable) The freeform tags associated with this resource, if any. Each tag is a simple key-value pair with no predefined name, type, or namespace/scope. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) The freeform tags associated with this resource, if any. Each tag is a simple key-value pair with no predefined name, type, or namespace/scope. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * Inventory ID to which an asset belongs.
     * 
     */
    @Import(name="inventoryId", required=true)
    private Output<String> inventoryId;

    /**
     * @return Inventory ID to which an asset belongs.
     * 
     */
    public Output<String> inventoryId() {
        return this.inventoryId;
    }

    /**
     * The source key to which the asset belongs.
     * 
     */
    @Import(name="sourceKey", required=true)
    private Output<String> sourceKey;

    /**
     * @return The source key to which the asset belongs.
     * 
     */
    public Output<String> sourceKey() {
        return this.sourceKey;
    }

    /**
     * (Updatable) Virtual machine related properties.
     * 
     */
    @Import(name="vm")
    private @Nullable Output<AssetVmArgs> vm;

    /**
     * @return (Updatable) Virtual machine related properties.
     * 
     */
    public Optional<Output<AssetVmArgs>> vm() {
        return Optional.ofNullable(this.vm);
    }

    /**
     * (Updatable) VMware vCenter related properties.
     * 
     */
    @Import(name="vmwareVcenter")
    private @Nullable Output<AssetVmwareVcenterArgs> vmwareVcenter;

    /**
     * @return (Updatable) VMware vCenter related properties.
     * 
     */
    public Optional<Output<AssetVmwareVcenterArgs>> vmwareVcenter() {
        return Optional.ofNullable(this.vmwareVcenter);
    }

    /**
     * (Updatable) VMware virtual machine related properties.
     * 
     */
    @Import(name="vmwareVm")
    private @Nullable Output<AssetVmwareVmArgs> vmwareVm;

    /**
     * @return (Updatable) VMware virtual machine related properties.
     * 
     */
    public Optional<Output<AssetVmwareVmArgs>> vmwareVm() {
        return Optional.ofNullable(this.vmwareVm);
    }

    private AssetArgs() {}

    private AssetArgs(AssetArgs $) {
        this.assetSourceIds = $.assetSourceIds;
        this.assetType = $.assetType;
        this.compartmentId = $.compartmentId;
        this.compute = $.compute;
        this.definedTags = $.definedTags;
        this.displayName = $.displayName;
        this.externalAssetKey = $.externalAssetKey;
        this.freeformTags = $.freeformTags;
        this.inventoryId = $.inventoryId;
        this.sourceKey = $.sourceKey;
        this.vm = $.vm;
        this.vmwareVcenter = $.vmwareVcenter;
        this.vmwareVm = $.vmwareVm;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(AssetArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private AssetArgs $;

        public Builder() {
            $ = new AssetArgs();
        }

        public Builder(AssetArgs defaults) {
            $ = new AssetArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param assetSourceIds (Updatable) List of asset source OCID.
         * 
         * @return builder
         * 
         */
        public Builder assetSourceIds(@Nullable Output<List<String>> assetSourceIds) {
            $.assetSourceIds = assetSourceIds;
            return this;
        }

        /**
         * @param assetSourceIds (Updatable) List of asset source OCID.
         * 
         * @return builder
         * 
         */
        public Builder assetSourceIds(List<String> assetSourceIds) {
            return assetSourceIds(Output.of(assetSourceIds));
        }

        /**
         * @param assetSourceIds (Updatable) List of asset source OCID.
         * 
         * @return builder
         * 
         */
        public Builder assetSourceIds(String... assetSourceIds) {
            return assetSourceIds(List.of(assetSourceIds));
        }

        /**
         * @param assetType (Updatable) The type of asset.
         * 
         * @return builder
         * 
         */
        public Builder assetType(Output<String> assetType) {
            $.assetType = assetType;
            return this;
        }

        /**
         * @param assetType (Updatable) The type of asset.
         * 
         * @return builder
         * 
         */
        public Builder assetType(String assetType) {
            return assetType(Output.of(assetType));
        }

        /**
         * @param compartmentId (Updatable) The OCID of the compartment that the asset belongs to.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) The OCID of the compartment that the asset belongs to.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param compute (Updatable) Compute related properties.
         * 
         * @return builder
         * 
         */
        public Builder compute(@Nullable Output<AssetComputeArgs> compute) {
            $.compute = compute;
            return this;
        }

        /**
         * @param compute (Updatable) Compute related properties.
         * 
         * @return builder
         * 
         */
        public Builder compute(AssetComputeArgs compute) {
            return compute(Output.of(compute));
        }

        /**
         * @param definedTags (Updatable) The defined tags associated with this resource, if any. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,Object>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) The defined tags associated with this resource, if any. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,Object> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param displayName (Updatable) Asset display name.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) Asset display name.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param externalAssetKey The key of the asset from the external environment.
         * 
         * @return builder
         * 
         */
        public Builder externalAssetKey(Output<String> externalAssetKey) {
            $.externalAssetKey = externalAssetKey;
            return this;
        }

        /**
         * @param externalAssetKey The key of the asset from the external environment.
         * 
         * @return builder
         * 
         */
        public Builder externalAssetKey(String externalAssetKey) {
            return externalAssetKey(Output.of(externalAssetKey));
        }

        /**
         * @param freeformTags (Updatable) The freeform tags associated with this resource, if any. Each tag is a simple key-value pair with no predefined name, type, or namespace/scope. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,Object>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) The freeform tags associated with this resource, if any. Each tag is a simple key-value pair with no predefined name, type, or namespace/scope. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,Object> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param inventoryId Inventory ID to which an asset belongs.
         * 
         * @return builder
         * 
         */
        public Builder inventoryId(Output<String> inventoryId) {
            $.inventoryId = inventoryId;
            return this;
        }

        /**
         * @param inventoryId Inventory ID to which an asset belongs.
         * 
         * @return builder
         * 
         */
        public Builder inventoryId(String inventoryId) {
            return inventoryId(Output.of(inventoryId));
        }

        /**
         * @param sourceKey The source key to which the asset belongs.
         * 
         * @return builder
         * 
         */
        public Builder sourceKey(Output<String> sourceKey) {
            $.sourceKey = sourceKey;
            return this;
        }

        /**
         * @param sourceKey The source key to which the asset belongs.
         * 
         * @return builder
         * 
         */
        public Builder sourceKey(String sourceKey) {
            return sourceKey(Output.of(sourceKey));
        }

        /**
         * @param vm (Updatable) Virtual machine related properties.
         * 
         * @return builder
         * 
         */
        public Builder vm(@Nullable Output<AssetVmArgs> vm) {
            $.vm = vm;
            return this;
        }

        /**
         * @param vm (Updatable) Virtual machine related properties.
         * 
         * @return builder
         * 
         */
        public Builder vm(AssetVmArgs vm) {
            return vm(Output.of(vm));
        }

        /**
         * @param vmwareVcenter (Updatable) VMware vCenter related properties.
         * 
         * @return builder
         * 
         */
        public Builder vmwareVcenter(@Nullable Output<AssetVmwareVcenterArgs> vmwareVcenter) {
            $.vmwareVcenter = vmwareVcenter;
            return this;
        }

        /**
         * @param vmwareVcenter (Updatable) VMware vCenter related properties.
         * 
         * @return builder
         * 
         */
        public Builder vmwareVcenter(AssetVmwareVcenterArgs vmwareVcenter) {
            return vmwareVcenter(Output.of(vmwareVcenter));
        }

        /**
         * @param vmwareVm (Updatable) VMware virtual machine related properties.
         * 
         * @return builder
         * 
         */
        public Builder vmwareVm(@Nullable Output<AssetVmwareVmArgs> vmwareVm) {
            $.vmwareVm = vmwareVm;
            return this;
        }

        /**
         * @param vmwareVm (Updatable) VMware virtual machine related properties.
         * 
         * @return builder
         * 
         */
        public Builder vmwareVm(AssetVmwareVmArgs vmwareVm) {
            return vmwareVm(Output.of(vmwareVm));
        }

        public AssetArgs build() {
            $.assetType = Objects.requireNonNull($.assetType, "expected parameter 'assetType' to be non-null");
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            $.externalAssetKey = Objects.requireNonNull($.externalAssetKey, "expected parameter 'externalAssetKey' to be non-null");
            $.inventoryId = Objects.requireNonNull($.inventoryId, "expected parameter 'inventoryId' to be non-null");
            $.sourceKey = Objects.requireNonNull($.sourceKey, "expected parameter 'sourceKey' to be non-null");
            return $;
        }
    }

}