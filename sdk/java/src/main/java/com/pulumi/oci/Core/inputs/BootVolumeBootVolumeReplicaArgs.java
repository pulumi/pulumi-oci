// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class BootVolumeBootVolumeReplicaArgs extends com.pulumi.resources.ResourceArgs {

    public static final BootVolumeBootVolumeReplicaArgs Empty = new BootVolumeBootVolumeReplicaArgs();

    /**
     * (Updatable) The availability domain of the boot volume replica.  Example: `Uocm:PHX-AD-1`
     * 
     */
    @Import(name="availabilityDomain", required=true)
    private Output<String> availabilityDomain;

    /**
     * @return (Updatable) The availability domain of the boot volume replica.  Example: `Uocm:PHX-AD-1`
     * 
     */
    public Output<String> availabilityDomain() {
        return this.availabilityDomain;
    }

    /**
     * The boot volume replica&#39;s Oracle ID (OCID).
     * 
     */
    @Import(name="bootVolumeReplicaId")
    private @Nullable Output<String> bootVolumeReplicaId;

    /**
     * @return The boot volume replica&#39;s Oracle ID (OCID).
     * 
     */
    public Optional<Output<String>> bootVolumeReplicaId() {
        return Optional.ofNullable(this.bootVolumeReplicaId);
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

    private BootVolumeBootVolumeReplicaArgs() {}

    private BootVolumeBootVolumeReplicaArgs(BootVolumeBootVolumeReplicaArgs $) {
        this.availabilityDomain = $.availabilityDomain;
        this.bootVolumeReplicaId = $.bootVolumeReplicaId;
        this.displayName = $.displayName;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(BootVolumeBootVolumeReplicaArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private BootVolumeBootVolumeReplicaArgs $;

        public Builder() {
            $ = new BootVolumeBootVolumeReplicaArgs();
        }

        public Builder(BootVolumeBootVolumeReplicaArgs defaults) {
            $ = new BootVolumeBootVolumeReplicaArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param availabilityDomain (Updatable) The availability domain of the boot volume replica.  Example: `Uocm:PHX-AD-1`
         * 
         * @return builder
         * 
         */
        public Builder availabilityDomain(Output<String> availabilityDomain) {
            $.availabilityDomain = availabilityDomain;
            return this;
        }

        /**
         * @param availabilityDomain (Updatable) The availability domain of the boot volume replica.  Example: `Uocm:PHX-AD-1`
         * 
         * @return builder
         * 
         */
        public Builder availabilityDomain(String availabilityDomain) {
            return availabilityDomain(Output.of(availabilityDomain));
        }

        /**
         * @param bootVolumeReplicaId The boot volume replica&#39;s Oracle ID (OCID).
         * 
         * @return builder
         * 
         */
        public Builder bootVolumeReplicaId(@Nullable Output<String> bootVolumeReplicaId) {
            $.bootVolumeReplicaId = bootVolumeReplicaId;
            return this;
        }

        /**
         * @param bootVolumeReplicaId The boot volume replica&#39;s Oracle ID (OCID).
         * 
         * @return builder
         * 
         */
        public Builder bootVolumeReplicaId(String bootVolumeReplicaId) {
            return bootVolumeReplicaId(Output.of(bootVolumeReplicaId));
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

        public BootVolumeBootVolumeReplicaArgs build() {
            $.availabilityDomain = Objects.requireNonNull($.availabilityDomain, "expected parameter 'availabilityDomain' to be non-null");
            return $;
        }
    }

}
