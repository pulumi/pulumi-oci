// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudMigrations.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.CloudMigrations.inputs.TargetAssetCompatibilityMessageArgs;
import com.pulumi.oci.CloudMigrations.inputs.TargetAssetEstimatedCostArgs;
import com.pulumi.oci.CloudMigrations.inputs.TargetAssetMigrationAssetArgs;
import com.pulumi.oci.CloudMigrations.inputs.TargetAssetRecommendedSpecArgs;
import com.pulumi.oci.CloudMigrations.inputs.TargetAssetTestSpecArgs;
import com.pulumi.oci.CloudMigrations.inputs.TargetAssetUserSpecArgs;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class TargetAssetState extends com.pulumi.resources.ResourceArgs {

    public static final TargetAssetState Empty = new TargetAssetState();

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
     * The OCID of the compartment.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return The OCID of the compartment.
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    /**
     * Messages about the compatibility issues.
     * 
     */
    @Import(name="compatibilityMessages")
    private @Nullable Output<List<TargetAssetCompatibilityMessageArgs>> compatibilityMessages;

    /**
     * @return Messages about the compatibility issues.
     * 
     */
    public Optional<Output<List<TargetAssetCompatibilityMessageArgs>>> compatibilityMessages() {
        return Optional.ofNullable(this.compatibilityMessages);
    }

    /**
     * Created resource identifier
     * 
     */
    @Import(name="createdResourceId")
    private @Nullable Output<String> createdResourceId;

    /**
     * @return Created resource identifier
     * 
     */
    public Optional<Output<String>> createdResourceId() {
        return Optional.ofNullable(this.createdResourceId);
    }

    /**
     * A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * Cost estimation description
     * 
     */
    @Import(name="estimatedCosts")
    private @Nullable Output<List<TargetAssetEstimatedCostArgs>> estimatedCosts;

    /**
     * @return Cost estimation description
     * 
     */
    public Optional<Output<List<TargetAssetEstimatedCostArgs>>> estimatedCosts() {
        return Optional.ofNullable(this.estimatedCosts);
    }

    /**
     * (Updatable) A boolean indicating whether the asset should be migrated.
     * 
     */
    @Import(name="isExcludedFromExecution")
    private @Nullable Output<Boolean> isExcludedFromExecution;

    /**
     * @return (Updatable) A boolean indicating whether the asset should be migrated.
     * 
     */
    public Optional<Output<Boolean>> isExcludedFromExecution() {
        return Optional.ofNullable(this.isExcludedFromExecution);
    }

    /**
     * A message describing the current state in more detail. For example, it can be used to provide actionable information for a resource in Failed state.
     * 
     */
    @Import(name="lifecycleDetails")
    private @Nullable Output<String> lifecycleDetails;

    /**
     * @return A message describing the current state in more detail. For example, it can be used to provide actionable information for a resource in Failed state.
     * 
     */
    public Optional<Output<String>> lifecycleDetails() {
        return Optional.ofNullable(this.lifecycleDetails);
    }

    /**
     * Description of the migration asset.
     * 
     */
    @Import(name="migrationAssets")
    private @Nullable Output<List<TargetAssetMigrationAssetArgs>> migrationAssets;

    /**
     * @return Description of the migration asset.
     * 
     */
    public Optional<Output<List<TargetAssetMigrationAssetArgs>>> migrationAssets() {
        return Optional.ofNullable(this.migrationAssets);
    }

    /**
     * OCID of the associated migration plan.
     * 
     */
    @Import(name="migrationPlanId")
    private @Nullable Output<String> migrationPlanId;

    /**
     * @return OCID of the associated migration plan.
     * 
     */
    public Optional<Output<String>> migrationPlanId() {
        return Optional.ofNullable(this.migrationPlanId);
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
    @Import(name="preferredShapeType")
    private @Nullable Output<String> preferredShapeType;

    /**
     * @return (Updatable) Preferred VM shape type that you provide.
     * 
     */
    public Optional<Output<String>> preferredShapeType() {
        return Optional.ofNullable(this.preferredShapeType);
    }

    /**
     * Instance launch details. Use the `sourceDetails` parameter to specify whether a boot volume or an image should be used to launch a new instance.
     * 
     */
    @Import(name="recommendedSpecs")
    private @Nullable Output<List<TargetAssetRecommendedSpecArgs>> recommendedSpecs;

    /**
     * @return Instance launch details. Use the `sourceDetails` parameter to specify whether a boot volume or an image should be used to launch a new instance.
     * 
     */
    public Optional<Output<List<TargetAssetRecommendedSpecArgs>>> recommendedSpecs() {
        return Optional.ofNullable(this.recommendedSpecs);
    }

    /**
     * The current state of the target asset.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return The current state of the target asset.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * Instance launch details. Use the `sourceDetails` parameter to specify whether a boot volume or an image should be used to launch a new instance.
     * 
     */
    @Import(name="testSpecs")
    private @Nullable Output<List<TargetAssetTestSpecArgs>> testSpecs;

    /**
     * @return Instance launch details. Use the `sourceDetails` parameter to specify whether a boot volume or an image should be used to launch a new instance.
     * 
     */
    public Optional<Output<List<TargetAssetTestSpecArgs>>> testSpecs() {
        return Optional.ofNullable(this.testSpecs);
    }

    /**
     * The time when the assessment was done. An RFC3339 formatted datetime string.
     * 
     */
    @Import(name="timeAssessed")
    private @Nullable Output<String> timeAssessed;

    /**
     * @return The time when the assessment was done. An RFC3339 formatted datetime string.
     * 
     */
    public Optional<Output<String>> timeAssessed() {
        return Optional.ofNullable(this.timeAssessed);
    }

    /**
     * The time when the target asset was created. An RFC3339 formatted datetime string.
     * 
     */
    @Import(name="timeCreated")
    private @Nullable Output<String> timeCreated;

    /**
     * @return The time when the target asset was created. An RFC3339 formatted datetime string.
     * 
     */
    public Optional<Output<String>> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    /**
     * The time when the target asset was updated. An RFC3339 formatted datetime string.
     * 
     */
    @Import(name="timeUpdated")
    private @Nullable Output<String> timeUpdated;

    /**
     * @return The time when the target asset was updated. An RFC3339 formatted datetime string.
     * 
     */
    public Optional<Output<String>> timeUpdated() {
        return Optional.ofNullable(this.timeUpdated);
    }

    /**
     * (Updatable) The type of target asset.
     * 
     */
    @Import(name="type")
    private @Nullable Output<String> type;

    /**
     * @return (Updatable) The type of target asset.
     * 
     */
    public Optional<Output<String>> type() {
        return Optional.ofNullable(this.type);
    }

    /**
     * (Updatable) Instance launch details. Use the `sourceDetails` parameter to specify whether a boot volume or an image should be used to launch a new instance.
     * 
     */
    @Import(name="userSpec")
    private @Nullable Output<TargetAssetUserSpecArgs> userSpec;

    /**
     * @return (Updatable) Instance launch details. Use the `sourceDetails` parameter to specify whether a boot volume or an image should be used to launch a new instance.
     * 
     */
    public Optional<Output<TargetAssetUserSpecArgs>> userSpec() {
        return Optional.ofNullable(this.userSpec);
    }

    private TargetAssetState() {}

    private TargetAssetState(TargetAssetState $) {
        this.blockVolumesPerformance = $.blockVolumesPerformance;
        this.compartmentId = $.compartmentId;
        this.compatibilityMessages = $.compatibilityMessages;
        this.createdResourceId = $.createdResourceId;
        this.displayName = $.displayName;
        this.estimatedCosts = $.estimatedCosts;
        this.isExcludedFromExecution = $.isExcludedFromExecution;
        this.lifecycleDetails = $.lifecycleDetails;
        this.migrationAssets = $.migrationAssets;
        this.migrationPlanId = $.migrationPlanId;
        this.msLicense = $.msLicense;
        this.preferredShapeType = $.preferredShapeType;
        this.recommendedSpecs = $.recommendedSpecs;
        this.state = $.state;
        this.testSpecs = $.testSpecs;
        this.timeAssessed = $.timeAssessed;
        this.timeCreated = $.timeCreated;
        this.timeUpdated = $.timeUpdated;
        this.type = $.type;
        this.userSpec = $.userSpec;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(TargetAssetState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private TargetAssetState $;

        public Builder() {
            $ = new TargetAssetState();
        }

        public Builder(TargetAssetState defaults) {
            $ = new TargetAssetState(Objects.requireNonNull(defaults));
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
         * @param compartmentId The OCID of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The OCID of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param compatibilityMessages Messages about the compatibility issues.
         * 
         * @return builder
         * 
         */
        public Builder compatibilityMessages(@Nullable Output<List<TargetAssetCompatibilityMessageArgs>> compatibilityMessages) {
            $.compatibilityMessages = compatibilityMessages;
            return this;
        }

        /**
         * @param compatibilityMessages Messages about the compatibility issues.
         * 
         * @return builder
         * 
         */
        public Builder compatibilityMessages(List<TargetAssetCompatibilityMessageArgs> compatibilityMessages) {
            return compatibilityMessages(Output.of(compatibilityMessages));
        }

        /**
         * @param compatibilityMessages Messages about the compatibility issues.
         * 
         * @return builder
         * 
         */
        public Builder compatibilityMessages(TargetAssetCompatibilityMessageArgs... compatibilityMessages) {
            return compatibilityMessages(List.of(compatibilityMessages));
        }

        /**
         * @param createdResourceId Created resource identifier
         * 
         * @return builder
         * 
         */
        public Builder createdResourceId(@Nullable Output<String> createdResourceId) {
            $.createdResourceId = createdResourceId;
            return this;
        }

        /**
         * @param createdResourceId Created resource identifier
         * 
         * @return builder
         * 
         */
        public Builder createdResourceId(String createdResourceId) {
            return createdResourceId(Output.of(createdResourceId));
        }

        /**
         * @param displayName A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param estimatedCosts Cost estimation description
         * 
         * @return builder
         * 
         */
        public Builder estimatedCosts(@Nullable Output<List<TargetAssetEstimatedCostArgs>> estimatedCosts) {
            $.estimatedCosts = estimatedCosts;
            return this;
        }

        /**
         * @param estimatedCosts Cost estimation description
         * 
         * @return builder
         * 
         */
        public Builder estimatedCosts(List<TargetAssetEstimatedCostArgs> estimatedCosts) {
            return estimatedCosts(Output.of(estimatedCosts));
        }

        /**
         * @param estimatedCosts Cost estimation description
         * 
         * @return builder
         * 
         */
        public Builder estimatedCosts(TargetAssetEstimatedCostArgs... estimatedCosts) {
            return estimatedCosts(List.of(estimatedCosts));
        }

        /**
         * @param isExcludedFromExecution (Updatable) A boolean indicating whether the asset should be migrated.
         * 
         * @return builder
         * 
         */
        public Builder isExcludedFromExecution(@Nullable Output<Boolean> isExcludedFromExecution) {
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
         * @param lifecycleDetails A message describing the current state in more detail. For example, it can be used to provide actionable information for a resource in Failed state.
         * 
         * @return builder
         * 
         */
        public Builder lifecycleDetails(@Nullable Output<String> lifecycleDetails) {
            $.lifecycleDetails = lifecycleDetails;
            return this;
        }

        /**
         * @param lifecycleDetails A message describing the current state in more detail. For example, it can be used to provide actionable information for a resource in Failed state.
         * 
         * @return builder
         * 
         */
        public Builder lifecycleDetails(String lifecycleDetails) {
            return lifecycleDetails(Output.of(lifecycleDetails));
        }

        /**
         * @param migrationAssets Description of the migration asset.
         * 
         * @return builder
         * 
         */
        public Builder migrationAssets(@Nullable Output<List<TargetAssetMigrationAssetArgs>> migrationAssets) {
            $.migrationAssets = migrationAssets;
            return this;
        }

        /**
         * @param migrationAssets Description of the migration asset.
         * 
         * @return builder
         * 
         */
        public Builder migrationAssets(List<TargetAssetMigrationAssetArgs> migrationAssets) {
            return migrationAssets(Output.of(migrationAssets));
        }

        /**
         * @param migrationAssets Description of the migration asset.
         * 
         * @return builder
         * 
         */
        public Builder migrationAssets(TargetAssetMigrationAssetArgs... migrationAssets) {
            return migrationAssets(List.of(migrationAssets));
        }

        /**
         * @param migrationPlanId OCID of the associated migration plan.
         * 
         * @return builder
         * 
         */
        public Builder migrationPlanId(@Nullable Output<String> migrationPlanId) {
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
        public Builder preferredShapeType(@Nullable Output<String> preferredShapeType) {
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
         * @param recommendedSpecs Instance launch details. Use the `sourceDetails` parameter to specify whether a boot volume or an image should be used to launch a new instance.
         * 
         * @return builder
         * 
         */
        public Builder recommendedSpecs(@Nullable Output<List<TargetAssetRecommendedSpecArgs>> recommendedSpecs) {
            $.recommendedSpecs = recommendedSpecs;
            return this;
        }

        /**
         * @param recommendedSpecs Instance launch details. Use the `sourceDetails` parameter to specify whether a boot volume or an image should be used to launch a new instance.
         * 
         * @return builder
         * 
         */
        public Builder recommendedSpecs(List<TargetAssetRecommendedSpecArgs> recommendedSpecs) {
            return recommendedSpecs(Output.of(recommendedSpecs));
        }

        /**
         * @param recommendedSpecs Instance launch details. Use the `sourceDetails` parameter to specify whether a boot volume or an image should be used to launch a new instance.
         * 
         * @return builder
         * 
         */
        public Builder recommendedSpecs(TargetAssetRecommendedSpecArgs... recommendedSpecs) {
            return recommendedSpecs(List.of(recommendedSpecs));
        }

        /**
         * @param state The current state of the target asset.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state The current state of the target asset.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param testSpecs Instance launch details. Use the `sourceDetails` parameter to specify whether a boot volume or an image should be used to launch a new instance.
         * 
         * @return builder
         * 
         */
        public Builder testSpecs(@Nullable Output<List<TargetAssetTestSpecArgs>> testSpecs) {
            $.testSpecs = testSpecs;
            return this;
        }

        /**
         * @param testSpecs Instance launch details. Use the `sourceDetails` parameter to specify whether a boot volume or an image should be used to launch a new instance.
         * 
         * @return builder
         * 
         */
        public Builder testSpecs(List<TargetAssetTestSpecArgs> testSpecs) {
            return testSpecs(Output.of(testSpecs));
        }

        /**
         * @param testSpecs Instance launch details. Use the `sourceDetails` parameter to specify whether a boot volume or an image should be used to launch a new instance.
         * 
         * @return builder
         * 
         */
        public Builder testSpecs(TargetAssetTestSpecArgs... testSpecs) {
            return testSpecs(List.of(testSpecs));
        }

        /**
         * @param timeAssessed The time when the assessment was done. An RFC3339 formatted datetime string.
         * 
         * @return builder
         * 
         */
        public Builder timeAssessed(@Nullable Output<String> timeAssessed) {
            $.timeAssessed = timeAssessed;
            return this;
        }

        /**
         * @param timeAssessed The time when the assessment was done. An RFC3339 formatted datetime string.
         * 
         * @return builder
         * 
         */
        public Builder timeAssessed(String timeAssessed) {
            return timeAssessed(Output.of(timeAssessed));
        }

        /**
         * @param timeCreated The time when the target asset was created. An RFC3339 formatted datetime string.
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(@Nullable Output<String> timeCreated) {
            $.timeCreated = timeCreated;
            return this;
        }

        /**
         * @param timeCreated The time when the target asset was created. An RFC3339 formatted datetime string.
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(String timeCreated) {
            return timeCreated(Output.of(timeCreated));
        }

        /**
         * @param timeUpdated The time when the target asset was updated. An RFC3339 formatted datetime string.
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(@Nullable Output<String> timeUpdated) {
            $.timeUpdated = timeUpdated;
            return this;
        }

        /**
         * @param timeUpdated The time when the target asset was updated. An RFC3339 formatted datetime string.
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(String timeUpdated) {
            return timeUpdated(Output.of(timeUpdated));
        }

        /**
         * @param type (Updatable) The type of target asset.
         * 
         * @return builder
         * 
         */
        public Builder type(@Nullable Output<String> type) {
            $.type = type;
            return this;
        }

        /**
         * @param type (Updatable) The type of target asset.
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
        public Builder userSpec(@Nullable Output<TargetAssetUserSpecArgs> userSpec) {
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

        public TargetAssetState build() {
            return $;
        }
    }

}
