// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Opa;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Boolean;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class OpaInstanceArgs extends com.pulumi.resources.ResourceArgs {

    public static final OpaInstanceArgs Empty = new OpaInstanceArgs();

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
     * Parameter specifying which entitlement to use for billing purposes
     * 
     */
    @Import(name="consumptionModel")
    private @Nullable Output<String> consumptionModel;

    /**
     * @return Parameter specifying which entitlement to use for billing purposes
     * 
     */
    public Optional<Output<String>> consumptionModel() {
        return Optional.ofNullable(this.consumptionModel);
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
     * (Updatable) Description of the Oracle Process Automation instance.
     * 
     */
    @Import(name="description")
    private @Nullable Output<String> description;

    /**
     * @return (Updatable) Description of the Oracle Process Automation instance.
     * 
     */
    public Optional<Output<String>> description() {
        return Optional.ofNullable(this.description);
    }

    /**
     * (Updatable) OpaInstance Identifier. User-friendly name for the instance. Avoid entering confidential information. You can change this value anytime.
     * 
     */
    @Import(name="displayName", required=true)
    private Output<String> displayName;

    /**
     * @return (Updatable) OpaInstance Identifier. User-friendly name for the instance. Avoid entering confidential information. You can change this value anytime.
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
     * IDCS Authentication token. This is required for all realms with IDCS. This property is optional, as it is not required for non-IDCS realms.
     * 
     */
    @Import(name="idcsAt")
    private @Nullable Output<String> idcsAt;

    /**
     * @return IDCS Authentication token. This is required for all realms with IDCS. This property is optional, as it is not required for non-IDCS realms.
     * 
     */
    public Optional<Output<String>> idcsAt() {
        return Optional.ofNullable(this.idcsAt);
    }

    /**
     * indicates if breakGlass is enabled for the opa instance.
     * 
     */
    @Import(name="isBreakglassEnabled")
    private @Nullable Output<Boolean> isBreakglassEnabled;

    /**
     * @return indicates if breakGlass is enabled for the opa instance.
     * 
     */
    public Optional<Output<Boolean>> isBreakglassEnabled() {
        return Optional.ofNullable(this.isBreakglassEnabled);
    }

    /**
     * MeteringType Identifier
     * 
     */
    @Import(name="meteringType")
    private @Nullable Output<String> meteringType;

    /**
     * @return MeteringType Identifier
     * 
     */
    public Optional<Output<String>> meteringType() {
        return Optional.ofNullable(this.meteringType);
    }

    /**
     * Shape of the instance.
     * 
     */
    @Import(name="shapeName", required=true)
    private Output<String> shapeName;

    /**
     * @return Shape of the instance.
     * 
     */
    public Output<String> shapeName() {
        return this.shapeName;
    }

    private OpaInstanceArgs() {}

    private OpaInstanceArgs(OpaInstanceArgs $) {
        this.compartmentId = $.compartmentId;
        this.consumptionModel = $.consumptionModel;
        this.definedTags = $.definedTags;
        this.description = $.description;
        this.displayName = $.displayName;
        this.freeformTags = $.freeformTags;
        this.idcsAt = $.idcsAt;
        this.isBreakglassEnabled = $.isBreakglassEnabled;
        this.meteringType = $.meteringType;
        this.shapeName = $.shapeName;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(OpaInstanceArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private OpaInstanceArgs $;

        public Builder() {
            $ = new OpaInstanceArgs();
        }

        public Builder(OpaInstanceArgs defaults) {
            $ = new OpaInstanceArgs(Objects.requireNonNull(defaults));
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
         * @param consumptionModel Parameter specifying which entitlement to use for billing purposes
         * 
         * @return builder
         * 
         */
        public Builder consumptionModel(@Nullable Output<String> consumptionModel) {
            $.consumptionModel = consumptionModel;
            return this;
        }

        /**
         * @param consumptionModel Parameter specifying which entitlement to use for billing purposes
         * 
         * @return builder
         * 
         */
        public Builder consumptionModel(String consumptionModel) {
            return consumptionModel(Output.of(consumptionModel));
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
         * @param description (Updatable) Description of the Oracle Process Automation instance.
         * 
         * @return builder
         * 
         */
        public Builder description(@Nullable Output<String> description) {
            $.description = description;
            return this;
        }

        /**
         * @param description (Updatable) Description of the Oracle Process Automation instance.
         * 
         * @return builder
         * 
         */
        public Builder description(String description) {
            return description(Output.of(description));
        }

        /**
         * @param displayName (Updatable) OpaInstance Identifier. User-friendly name for the instance. Avoid entering confidential information. You can change this value anytime.
         * 
         * @return builder
         * 
         */
        public Builder displayName(Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) OpaInstance Identifier. User-friendly name for the instance. Avoid entering confidential information. You can change this value anytime.
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
         * @param idcsAt IDCS Authentication token. This is required for all realms with IDCS. This property is optional, as it is not required for non-IDCS realms.
         * 
         * @return builder
         * 
         */
        public Builder idcsAt(@Nullable Output<String> idcsAt) {
            $.idcsAt = idcsAt;
            return this;
        }

        /**
         * @param idcsAt IDCS Authentication token. This is required for all realms with IDCS. This property is optional, as it is not required for non-IDCS realms.
         * 
         * @return builder
         * 
         */
        public Builder idcsAt(String idcsAt) {
            return idcsAt(Output.of(idcsAt));
        }

        /**
         * @param isBreakglassEnabled indicates if breakGlass is enabled for the opa instance.
         * 
         * @return builder
         * 
         */
        public Builder isBreakglassEnabled(@Nullable Output<Boolean> isBreakglassEnabled) {
            $.isBreakglassEnabled = isBreakglassEnabled;
            return this;
        }

        /**
         * @param isBreakglassEnabled indicates if breakGlass is enabled for the opa instance.
         * 
         * @return builder
         * 
         */
        public Builder isBreakglassEnabled(Boolean isBreakglassEnabled) {
            return isBreakglassEnabled(Output.of(isBreakglassEnabled));
        }

        /**
         * @param meteringType MeteringType Identifier
         * 
         * @return builder
         * 
         */
        public Builder meteringType(@Nullable Output<String> meteringType) {
            $.meteringType = meteringType;
            return this;
        }

        /**
         * @param meteringType MeteringType Identifier
         * 
         * @return builder
         * 
         */
        public Builder meteringType(String meteringType) {
            return meteringType(Output.of(meteringType));
        }

        /**
         * @param shapeName Shape of the instance.
         * 
         * @return builder
         * 
         */
        public Builder shapeName(Output<String> shapeName) {
            $.shapeName = shapeName;
            return this;
        }

        /**
         * @param shapeName Shape of the instance.
         * 
         * @return builder
         * 
         */
        public Builder shapeName(String shapeName) {
            return shapeName(Output.of(shapeName));
        }

        public OpaInstanceArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            $.displayName = Objects.requireNonNull($.displayName, "expected parameter 'displayName' to be non-null");
            $.shapeName = Objects.requireNonNull($.shapeName, "expected parameter 'shapeName' to be non-null");
            return $;
        }
    }

}