// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Apm.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Boolean;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ApmDomainState extends com.pulumi.resources.ResourceArgs {

    public static final ApmDomainState Empty = new ApmDomainState();

    /**
     * (Updatable) The OCID of the compartment corresponding to the APM domain.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return (Updatable) The OCID of the compartment corresponding to the APM domain.
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    /**
     * The endpoint where the APM agents upload their observations and metrics.
     * 
     */
    @Import(name="dataUploadEndpoint")
    private @Nullable Output<String> dataUploadEndpoint;

    /**
     * @return The endpoint where the APM agents upload their observations and metrics.
     * 
     */
    public Optional<Output<String>> dataUploadEndpoint() {
        return Optional.ofNullable(this.dataUploadEndpoint);
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
     * (Updatable) Description of the APM domain.
     * 
     */
    @Import(name="description")
    private @Nullable Output<String> description;

    /**
     * @return (Updatable) Description of the APM domain.
     * 
     */
    public Optional<Output<String>> description() {
        return Optional.ofNullable(this.description);
    }

    /**
     * (Updatable) Display name of the APM domain.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return (Updatable) Display name of the APM domain.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
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
     * Indicates whether this is an &#34;Always Free&#34; resource. The default value is false.
     * 
     */
    @Import(name="isFreeTier")
    private @Nullable Output<Boolean> isFreeTier;

    /**
     * @return Indicates whether this is an &#34;Always Free&#34; resource. The default value is false.
     * 
     */
    public Optional<Output<Boolean>> isFreeTier() {
        return Optional.ofNullable(this.isFreeTier);
    }

    /**
     * The current lifecycle state of the APM domain.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return The current lifecycle state of the APM domain.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * The time the APM domain was created, expressed in RFC 3339 timestamp format.
     * 
     */
    @Import(name="timeCreated")
    private @Nullable Output<String> timeCreated;

    /**
     * @return The time the APM domain was created, expressed in RFC 3339 timestamp format.
     * 
     */
    public Optional<Output<String>> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    /**
     * The time the APM domain was updated, expressed in RFC 3339 timestamp format.
     * 
     */
    @Import(name="timeUpdated")
    private @Nullable Output<String> timeUpdated;

    /**
     * @return The time the APM domain was updated, expressed in RFC 3339 timestamp format.
     * 
     */
    public Optional<Output<String>> timeUpdated() {
        return Optional.ofNullable(this.timeUpdated);
    }

    private ApmDomainState() {}

    private ApmDomainState(ApmDomainState $) {
        this.compartmentId = $.compartmentId;
        this.dataUploadEndpoint = $.dataUploadEndpoint;
        this.definedTags = $.definedTags;
        this.description = $.description;
        this.displayName = $.displayName;
        this.freeformTags = $.freeformTags;
        this.isFreeTier = $.isFreeTier;
        this.state = $.state;
        this.timeCreated = $.timeCreated;
        this.timeUpdated = $.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ApmDomainState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ApmDomainState $;

        public Builder() {
            $ = new ApmDomainState();
        }

        public Builder(ApmDomainState defaults) {
            $ = new ApmDomainState(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId (Updatable) The OCID of the compartment corresponding to the APM domain.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) The OCID of the compartment corresponding to the APM domain.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param dataUploadEndpoint The endpoint where the APM agents upload their observations and metrics.
         * 
         * @return builder
         * 
         */
        public Builder dataUploadEndpoint(@Nullable Output<String> dataUploadEndpoint) {
            $.dataUploadEndpoint = dataUploadEndpoint;
            return this;
        }

        /**
         * @param dataUploadEndpoint The endpoint where the APM agents upload their observations and metrics.
         * 
         * @return builder
         * 
         */
        public Builder dataUploadEndpoint(String dataUploadEndpoint) {
            return dataUploadEndpoint(Output.of(dataUploadEndpoint));
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
         * @param description (Updatable) Description of the APM domain.
         * 
         * @return builder
         * 
         */
        public Builder description(@Nullable Output<String> description) {
            $.description = description;
            return this;
        }

        /**
         * @param description (Updatable) Description of the APM domain.
         * 
         * @return builder
         * 
         */
        public Builder description(String description) {
            return description(Output.of(description));
        }

        /**
         * @param displayName (Updatable) Display name of the APM domain.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) Display name of the APM domain.
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
         * @param isFreeTier Indicates whether this is an &#34;Always Free&#34; resource. The default value is false.
         * 
         * @return builder
         * 
         */
        public Builder isFreeTier(@Nullable Output<Boolean> isFreeTier) {
            $.isFreeTier = isFreeTier;
            return this;
        }

        /**
         * @param isFreeTier Indicates whether this is an &#34;Always Free&#34; resource. The default value is false.
         * 
         * @return builder
         * 
         */
        public Builder isFreeTier(Boolean isFreeTier) {
            return isFreeTier(Output.of(isFreeTier));
        }

        /**
         * @param state The current lifecycle state of the APM domain.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state The current lifecycle state of the APM domain.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param timeCreated The time the APM domain was created, expressed in RFC 3339 timestamp format.
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(@Nullable Output<String> timeCreated) {
            $.timeCreated = timeCreated;
            return this;
        }

        /**
         * @param timeCreated The time the APM domain was created, expressed in RFC 3339 timestamp format.
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(String timeCreated) {
            return timeCreated(Output.of(timeCreated));
        }

        /**
         * @param timeUpdated The time the APM domain was updated, expressed in RFC 3339 timestamp format.
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(@Nullable Output<String> timeUpdated) {
            $.timeUpdated = timeUpdated;
            return this;
        }

        /**
         * @param timeUpdated The time the APM domain was updated, expressed in RFC 3339 timestamp format.
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(String timeUpdated) {
            return timeUpdated(Output.of(timeUpdated));
        }

        public ApmDomainState build() {
            return $;
        }
    }

}