// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.VisualBuilder.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class VbInstanceAttachmentArgs extends com.pulumi.resources.ResourceArgs {

    public static final VbInstanceAttachmentArgs Empty = new VbInstanceAttachmentArgs();

    /**
     * * If role == `PARENT`, the attached instance was created by this service instance
     * * If role == `CHILD`, this instance was created from attached instance on behalf of a user
     * 
     */
    @Import(name="isImplicit")
    private @Nullable Output<Boolean> isImplicit;

    /**
     * @return * If role == `PARENT`, the attached instance was created by this service instance
     * * If role == `CHILD`, this instance was created from attached instance on behalf of a user
     * 
     */
    public Optional<Output<Boolean>> isImplicit() {
        return Optional.ofNullable(this.isImplicit);
    }

    /**
     * The OCID of the target instance (which could be any other Oracle Cloud Infrastructure PaaS/SaaS resource), to which this instance is attached.
     * 
     */
    @Import(name="targetId")
    private @Nullable Output<String> targetId;

    /**
     * @return The OCID of the target instance (which could be any other Oracle Cloud Infrastructure PaaS/SaaS resource), to which this instance is attached.
     * 
     */
    public Optional<Output<String>> targetId() {
        return Optional.ofNullable(this.targetId);
    }

    /**
     * The dataplane instance URL of the attached instance
     * 
     */
    @Import(name="targetInstanceUrl")
    private @Nullable Output<String> targetInstanceUrl;

    /**
     * @return The dataplane instance URL of the attached instance
     * 
     */
    public Optional<Output<String>> targetInstanceUrl() {
        return Optional.ofNullable(this.targetInstanceUrl);
    }

    /**
     * The role of the target attachment.
     * 
     */
    @Import(name="targetRole")
    private @Nullable Output<String> targetRole;

    /**
     * @return The role of the target attachment.
     * 
     */
    public Optional<Output<String>> targetRole() {
        return Optional.ofNullable(this.targetRole);
    }

    /**
     * The type of the target instance, such as &#34;FUSION&#34;.
     * 
     */
    @Import(name="targetServiceType")
    private @Nullable Output<String> targetServiceType;

    /**
     * @return The type of the target instance, such as &#34;FUSION&#34;.
     * 
     */
    public Optional<Output<String>> targetServiceType() {
        return Optional.ofNullable(this.targetServiceType);
    }

    private VbInstanceAttachmentArgs() {}

    private VbInstanceAttachmentArgs(VbInstanceAttachmentArgs $) {
        this.isImplicit = $.isImplicit;
        this.targetId = $.targetId;
        this.targetInstanceUrl = $.targetInstanceUrl;
        this.targetRole = $.targetRole;
        this.targetServiceType = $.targetServiceType;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(VbInstanceAttachmentArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private VbInstanceAttachmentArgs $;

        public Builder() {
            $ = new VbInstanceAttachmentArgs();
        }

        public Builder(VbInstanceAttachmentArgs defaults) {
            $ = new VbInstanceAttachmentArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param isImplicit * If role == `PARENT`, the attached instance was created by this service instance
         * * If role == `CHILD`, this instance was created from attached instance on behalf of a user
         * 
         * @return builder
         * 
         */
        public Builder isImplicit(@Nullable Output<Boolean> isImplicit) {
            $.isImplicit = isImplicit;
            return this;
        }

        /**
         * @param isImplicit * If role == `PARENT`, the attached instance was created by this service instance
         * * If role == `CHILD`, this instance was created from attached instance on behalf of a user
         * 
         * @return builder
         * 
         */
        public Builder isImplicit(Boolean isImplicit) {
            return isImplicit(Output.of(isImplicit));
        }

        /**
         * @param targetId The OCID of the target instance (which could be any other Oracle Cloud Infrastructure PaaS/SaaS resource), to which this instance is attached.
         * 
         * @return builder
         * 
         */
        public Builder targetId(@Nullable Output<String> targetId) {
            $.targetId = targetId;
            return this;
        }

        /**
         * @param targetId The OCID of the target instance (which could be any other Oracle Cloud Infrastructure PaaS/SaaS resource), to which this instance is attached.
         * 
         * @return builder
         * 
         */
        public Builder targetId(String targetId) {
            return targetId(Output.of(targetId));
        }

        /**
         * @param targetInstanceUrl The dataplane instance URL of the attached instance
         * 
         * @return builder
         * 
         */
        public Builder targetInstanceUrl(@Nullable Output<String> targetInstanceUrl) {
            $.targetInstanceUrl = targetInstanceUrl;
            return this;
        }

        /**
         * @param targetInstanceUrl The dataplane instance URL of the attached instance
         * 
         * @return builder
         * 
         */
        public Builder targetInstanceUrl(String targetInstanceUrl) {
            return targetInstanceUrl(Output.of(targetInstanceUrl));
        }

        /**
         * @param targetRole The role of the target attachment.
         * 
         * @return builder
         * 
         */
        public Builder targetRole(@Nullable Output<String> targetRole) {
            $.targetRole = targetRole;
            return this;
        }

        /**
         * @param targetRole The role of the target attachment.
         * 
         * @return builder
         * 
         */
        public Builder targetRole(String targetRole) {
            return targetRole(Output.of(targetRole));
        }

        /**
         * @param targetServiceType The type of the target instance, such as &#34;FUSION&#34;.
         * 
         * @return builder
         * 
         */
        public Builder targetServiceType(@Nullable Output<String> targetServiceType) {
            $.targetServiceType = targetServiceType;
            return this;
        }

        /**
         * @param targetServiceType The type of the target instance, such as &#34;FUSION&#34;.
         * 
         * @return builder
         * 
         */
        public Builder targetServiceType(String targetServiceType) {
            return targetServiceType(Output.of(targetServiceType));
        }

        public VbInstanceAttachmentArgs build() {
            return $;
        }
    }

}