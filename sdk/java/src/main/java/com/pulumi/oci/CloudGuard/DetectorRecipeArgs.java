// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudGuard;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.CloudGuard.inputs.DetectorRecipeDetectorRuleArgs;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DetectorRecipeArgs extends com.pulumi.resources.ResourceArgs {

    public static final DetectorRecipeArgs Empty = new DetectorRecipeArgs();

    /**
     * (Updatable) Compartment Identifier
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return (Updatable) Compartment Identifier
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
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
     * (Updatable) Description for DetectorRecipeDetectorRule.
     * 
     */
    @Import(name="description")
    private @Nullable Output<String> description;

    /**
     * @return (Updatable) Description for DetectorRecipeDetectorRule.
     * 
     */
    public Optional<Output<String>> description() {
        return Optional.ofNullable(this.description);
    }

    /**
     * detector for the rule
     * 
     */
    @Import(name="detector")
    private @Nullable Output<String> detector;

    /**
     * @return detector for the rule
     * 
     */
    public Optional<Output<String>> detector() {
        return Optional.ofNullable(this.detector);
    }

    /**
     * (Updatable) Detector Rules to override from source detector recipe
     * 
     */
    @Import(name="detectorRules")
    private @Nullable Output<List<DetectorRecipeDetectorRuleArgs>> detectorRules;

    /**
     * @return (Updatable) Detector Rules to override from source detector recipe
     * 
     */
    public Optional<Output<List<DetectorRecipeDetectorRuleArgs>>> detectorRules() {
        return Optional.ofNullable(this.detectorRules);
    }

    /**
     * (Updatable) Detector recipe display name.
     * 
     */
    @Import(name="displayName", required=true)
    private Output<String> displayName;

    /**
     * @return (Updatable) Detector recipe display name.
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
     * The id of the source detector recipe.
     * 
     */
    @Import(name="sourceDetectorRecipeId")
    private @Nullable Output<String> sourceDetectorRecipeId;

    /**
     * @return The id of the source detector recipe.
     * 
     */
    public Optional<Output<String>> sourceDetectorRecipeId() {
        return Optional.ofNullable(this.sourceDetectorRecipeId);
    }

    private DetectorRecipeArgs() {}

    private DetectorRecipeArgs(DetectorRecipeArgs $) {
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.description = $.description;
        this.detector = $.detector;
        this.detectorRules = $.detectorRules;
        this.displayName = $.displayName;
        this.freeformTags = $.freeformTags;
        this.sourceDetectorRecipeId = $.sourceDetectorRecipeId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DetectorRecipeArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DetectorRecipeArgs $;

        public Builder() {
            $ = new DetectorRecipeArgs();
        }

        public Builder(DetectorRecipeArgs defaults) {
            $ = new DetectorRecipeArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId (Updatable) Compartment Identifier
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) Compartment Identifier
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
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
         * @param description (Updatable) Description for DetectorRecipeDetectorRule.
         * 
         * @return builder
         * 
         */
        public Builder description(@Nullable Output<String> description) {
            $.description = description;
            return this;
        }

        /**
         * @param description (Updatable) Description for DetectorRecipeDetectorRule.
         * 
         * @return builder
         * 
         */
        public Builder description(String description) {
            return description(Output.of(description));
        }

        /**
         * @param detector detector for the rule
         * 
         * @return builder
         * 
         */
        public Builder detector(@Nullable Output<String> detector) {
            $.detector = detector;
            return this;
        }

        /**
         * @param detector detector for the rule
         * 
         * @return builder
         * 
         */
        public Builder detector(String detector) {
            return detector(Output.of(detector));
        }

        /**
         * @param detectorRules (Updatable) Detector Rules to override from source detector recipe
         * 
         * @return builder
         * 
         */
        public Builder detectorRules(@Nullable Output<List<DetectorRecipeDetectorRuleArgs>> detectorRules) {
            $.detectorRules = detectorRules;
            return this;
        }

        /**
         * @param detectorRules (Updatable) Detector Rules to override from source detector recipe
         * 
         * @return builder
         * 
         */
        public Builder detectorRules(List<DetectorRecipeDetectorRuleArgs> detectorRules) {
            return detectorRules(Output.of(detectorRules));
        }

        /**
         * @param detectorRules (Updatable) Detector Rules to override from source detector recipe
         * 
         * @return builder
         * 
         */
        public Builder detectorRules(DetectorRecipeDetectorRuleArgs... detectorRules) {
            return detectorRules(List.of(detectorRules));
        }

        /**
         * @param displayName (Updatable) Detector recipe display name.
         * 
         * @return builder
         * 
         */
        public Builder displayName(Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) Detector recipe display name.
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
         * @param sourceDetectorRecipeId The id of the source detector recipe.
         * 
         * @return builder
         * 
         */
        public Builder sourceDetectorRecipeId(@Nullable Output<String> sourceDetectorRecipeId) {
            $.sourceDetectorRecipeId = sourceDetectorRecipeId;
            return this;
        }

        /**
         * @param sourceDetectorRecipeId The id of the source detector recipe.
         * 
         * @return builder
         * 
         */
        public Builder sourceDetectorRecipeId(String sourceDetectorRecipeId) {
            return sourceDetectorRecipeId(Output.of(sourceDetectorRecipeId));
        }

        public DetectorRecipeArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            $.displayName = Objects.requireNonNull($.displayName, "expected parameter 'displayName' to be non-null");
            return $;
        }
    }

}