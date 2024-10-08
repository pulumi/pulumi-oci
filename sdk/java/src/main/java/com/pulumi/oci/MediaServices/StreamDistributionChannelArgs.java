// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.MediaServices;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.MediaServices.inputs.StreamDistributionChannelLockArgs;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class StreamDistributionChannelArgs extends com.pulumi.resources.ResourceArgs {

    public static final StreamDistributionChannelArgs Empty = new StreamDistributionChannelArgs();

    /**
     * (Updatable) Compartment Identifier.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return (Updatable) Compartment Identifier.
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
    private @Nullable Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) Stream Distribution Channel display name. Avoid entering confidential information.
     * 
     */
    @Import(name="displayName", required=true)
    private Output<String> displayName;

    /**
     * @return (Updatable) Stream Distribution Channel display name. Avoid entering confidential information.
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
    private @Nullable Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    @Import(name="isLockOverride")
    private @Nullable Output<Boolean> isLockOverride;

    public Optional<Output<Boolean>> isLockOverride() {
        return Optional.ofNullable(this.isLockOverride);
    }

    /**
     * Locks associated with this resource.
     * 
     */
    @Import(name="locks")
    private @Nullable Output<List<StreamDistributionChannelLockArgs>> locks;

    /**
     * @return Locks associated with this resource.
     * 
     */
    public Optional<Output<List<StreamDistributionChannelLockArgs>>> locks() {
        return Optional.ofNullable(this.locks);
    }

    private StreamDistributionChannelArgs() {}

    private StreamDistributionChannelArgs(StreamDistributionChannelArgs $) {
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.displayName = $.displayName;
        this.freeformTags = $.freeformTags;
        this.isLockOverride = $.isLockOverride;
        this.locks = $.locks;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(StreamDistributionChannelArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private StreamDistributionChannelArgs $;

        public Builder() {
            $ = new StreamDistributionChannelArgs();
        }

        public Builder(StreamDistributionChannelArgs defaults) {
            $ = new StreamDistributionChannelArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId (Updatable) Compartment Identifier.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) Compartment Identifier.
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
        public Builder definedTags(@Nullable Output<Map<String,String>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,String> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param displayName (Updatable) Stream Distribution Channel display name. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) Stream Distribution Channel display name. Avoid entering confidential information.
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
        public Builder freeformTags(@Nullable Output<Map<String,String>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,String> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        public Builder isLockOverride(@Nullable Output<Boolean> isLockOverride) {
            $.isLockOverride = isLockOverride;
            return this;
        }

        public Builder isLockOverride(Boolean isLockOverride) {
            return isLockOverride(Output.of(isLockOverride));
        }

        /**
         * @param locks Locks associated with this resource.
         * 
         * @return builder
         * 
         */
        public Builder locks(@Nullable Output<List<StreamDistributionChannelLockArgs>> locks) {
            $.locks = locks;
            return this;
        }

        /**
         * @param locks Locks associated with this resource.
         * 
         * @return builder
         * 
         */
        public Builder locks(List<StreamDistributionChannelLockArgs> locks) {
            return locks(Output.of(locks));
        }

        /**
         * @param locks Locks associated with this resource.
         * 
         * @return builder
         * 
         */
        public Builder locks(StreamDistributionChannelLockArgs... locks) {
            return locks(List.of(locks));
        }

        public StreamDistributionChannelArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("StreamDistributionChannelArgs", "compartmentId");
            }
            if ($.displayName == null) {
                throw new MissingRequiredPropertyException("StreamDistributionChannelArgs", "displayName");
            }
            return $;
        }
    }

}
