// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudMigrations;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.CloudMigrations.inputs.TargetAssetUserSpecArgs;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class TargetAssetArgs extends com.pulumi.resources.ResourceArgs {

    public static final TargetAssetArgs Empty = new TargetAssetArgs();

    /**
     * (Updatable) Performance of the block volumes.
     * 
     */
    @Import(name="blockVolumesPerformance")
    private @Nullable Output<Integer> blockVolumesPerformance;

    /**
     * @return (Updatable) Performance of the block volumes.
     * 
     */
    public Optional<Output<Integer>> blockVolumesPerformance() {
        return Optional.ofNullable(this.blockVolumesPerformance);
    }

    /**
     * (Updatable) A boolean indicating whether the asset should be migrated.
     * 
     */
    @Import(name="isExcludedFromExecution", required=true)
    private Output<Boolean> isExcludedFromExecution;

    /**
     * @return (Updatable) A boolean indicating whether the asset should be migrated.
     * 
     */
    public Output<Boolean> isExcludedFromExecution() {
        return this.isExcludedFromExecution;
    }

    /**
     * OCID of the associated migration plan.
     * 
     */
    @Import(name="migrationPlanId", required=true)
    private Output<String> migrationPlanId;

    /**
     * @return OCID of the associated migration plan.
     * 
     */
    public Output<String> migrationPlanId() {
        return this.migrationPlanId;
    }

    /**
     * (Updatable) Microsoft license for the VM configuration.
     * 
     */
    @Import(name="msLicense")
    private @Nullable Output<String> msLicense;

    /**
     * @return (Updatable) Microsoft license for the VM configuration.
     * 
     */
    public Optional<Output<String>> msLicense() {
        return Optional.ofNullable(this.msLicense);
    }

    /**
     * (Updatable) Preferred VM shape type that you provide.
     * 
     */
    @Import(name="preferredShapeType", required=true)
    private Output<String> preferredShapeType;

    /**
     * @return (Updatable) Preferred VM shape type that you provide.
     * 
     */
    public Output<String> preferredShapeType() {
        return this.preferredShapeType;
    }

    /**
     * (Updatable) The type of action to run when the instance is interrupted for eviction.
     * 
     */
    @Import(name="type", required=true)
    private Output<String> type;

    /**
     * @return (Updatable) The type of action to run when the instance is interrupted for eviction.
     * 
     */
    public Output<String> type() {
        return this.type;
    }

    /**
     * (Updatable) Instance launch details. Use the `sourceDetails` parameter to specify whether a boot volume or an image should be used to launch a new instance.
     * 
     */
    @Import(name="userSpec", required=true)
    private Output<TargetAssetUserSpecArgs> userSpec;

    /**
     * @return (Updatable) Instance launch details. Use the `sourceDetails` parameter to specify whether a boot volume or an image should be used to launch a new instance.
     * 
     */
    public Output<TargetAssetUserSpecArgs> userSpec() {
        return this.userSpec;
    }

    private TargetAssetArgs() {}

    private TargetAssetArgs(TargetAssetArgs $) {
        this.blockVolumesPerformance = $.blockVolumesPerformance;
        this.isExcludedFromExecution = $.isExcludedFromExecution;
        this.migrationPlanId = $.migrationPlanId;
        this.msLicense = $.msLicense;
        this.preferredShapeType = $.preferredShapeType;
        this.type = $.type;
        this.userSpec = $.userSpec;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(TargetAssetArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private TargetAssetArgs $;

        public Builder() {
            $ = new TargetAssetArgs();
        }

        public Builder(TargetAssetArgs defaults) {
            $ = new TargetAssetArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param blockVolumesPerformance (Updatable) Performance of the block volumes.
         * 
         * @return builder
         * 
         */
        public Builder blockVolumesPerformance(@Nullable Output<Integer> blockVolumesPerformance) {
            $.blockVolumesPerformance = blockVolumesPerformance;
            return this;
        }

        /**
         * @param blockVolumesPerformance (Updatable) Performance of the block volumes.
         * 
         * @return builder
         * 
         */
        public Builder blockVolumesPerformance(Integer blockVolumesPerformance) {
            return blockVolumesPerformance(Output.of(blockVolumesPerformance));
        }

        /**
         * @param isExcludedFromExecution (Updatable) A boolean indicating whether the asset should be migrated.
         * 
         * @return builder
         * 
         */
        public Builder isExcludedFromExecution(Output<Boolean> isExcludedFromExecution) {
            $.isExcludedFromExecution = isExcludedFromExecution;
            return this;
        }

        /**
         * @param isExcludedFromExecution (Updatable) A boolean indicating whether the asset should be migrated.
         * 
         * @return builder
         * 
         */
        public Builder isExcludedFromExecution(Boolean isExcludedFromExecution) {
            return isExcludedFromExecution(Output.of(isExcludedFromExecution));
        }

        /**
         * @param migrationPlanId OCID of the associated migration plan.
         * 
         * @return builder
         * 
         */
        public Builder migrationPlanId(Output<String> migrationPlanId) {
            $.migrationPlanId = migrationPlanId;
            return this;
        }

        /**
         * @param migrationPlanId OCID of the associated migration plan.
         * 
         * @return builder
         * 
         */
        public Builder migrationPlanId(String migrationPlanId) {
            return migrationPlanId(Output.of(migrationPlanId));
        }

        /**
         * @param msLicense (Updatable) Microsoft license for the VM configuration.
         * 
         * @return builder
         * 
         */
        public Builder msLicense(@Nullable Output<String> msLicense) {
            $.msLicense = msLicense;
            return this;
        }

        /**
         * @param msLicense (Updatable) Microsoft license for the VM configuration.
         * 
         * @return builder
         * 
         */
        public Builder msLicense(String msLicense) {
            return msLicense(Output.of(msLicense));
        }

        /**
         * @param preferredShapeType (Updatable) Preferred VM shape type that you provide.
         * 
         * @return builder
         * 
         */
        public Builder preferredShapeType(Output<String> preferredShapeType) {
            $.preferredShapeType = preferredShapeType;
            return this;
        }

        /**
         * @param preferredShapeType (Updatable) Preferred VM shape type that you provide.
         * 
         * @return builder
         * 
         */
        public Builder preferredShapeType(String preferredShapeType) {
            return preferredShapeType(Output.of(preferredShapeType));
        }

        /**
         * @param type (Updatable) The type of action to run when the instance is interrupted for eviction.
         * 
         * @return builder
         * 
         */
        public Builder type(Output<String> type) {
            $.type = type;
            return this;
        }

        /**
         * @param type (Updatable) The type of action to run when the instance is interrupted for eviction.
         * 
         * @return builder
         * 
         */
        public Builder type(String type) {
            return type(Output.of(type));
        }

        /**
         * @param userSpec (Updatable) Instance launch details. Use the `sourceDetails` parameter to specify whether a boot volume or an image should be used to launch a new instance.
         * 
         * @return builder
         * 
         */
        public Builder userSpec(Output<TargetAssetUserSpecArgs> userSpec) {
            $.userSpec = userSpec;
            return this;
        }

        /**
         * @param userSpec (Updatable) Instance launch details. Use the `sourceDetails` parameter to specify whether a boot volume or an image should be used to launch a new instance.
         * 
         * @return builder
         * 
         */
        public Builder userSpec(TargetAssetUserSpecArgs userSpec) {
            return userSpec(Output.of(userSpec));
        }

        public TargetAssetArgs build() {
            $.isExcludedFromExecution = Objects.requireNonNull($.isExcludedFromExecution, "expected parameter 'isExcludedFromExecution' to be non-null");
            $.migrationPlanId = Objects.requireNonNull($.migrationPlanId, "expected parameter 'migrationPlanId' to be non-null");
            $.preferredShapeType = Objects.requireNonNull($.preferredShapeType, "expected parameter 'preferredShapeType' to be non-null");
            $.type = Objects.requireNonNull($.type, "expected parameter 'type' to be non-null");
            $.userSpec = Objects.requireNonNull($.userSpec, "expected parameter 'userSpec' to be non-null");
            return $;
        }
    }

}