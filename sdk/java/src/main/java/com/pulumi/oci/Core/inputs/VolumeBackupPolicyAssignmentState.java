// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class VolumeBackupPolicyAssignmentState extends com.pulumi.resources.ResourceArgs {

    public static final VolumeBackupPolicyAssignmentState Empty = new VolumeBackupPolicyAssignmentState();

    /**
     * The OCID of the volume to assign the policy to.
     * 
     */
    @Import(name="assetId")
    private @Nullable Output<String> assetId;

    /**
     * @return The OCID of the volume to assign the policy to.
     * 
     */
    public Optional<Output<String>> assetId() {
        return Optional.ofNullable(this.assetId);
    }

    /**
     * The OCID of the volume backup policy to assign to the volume.
     * 
     */
    @Import(name="policyId")
    private @Nullable Output<String> policyId;

    /**
     * @return The OCID of the volume backup policy to assign to the volume.
     * 
     */
    public Optional<Output<String>> policyId() {
        return Optional.ofNullable(this.policyId);
    }

    /**
     * The date and time the volume backup policy was assigned to the volume. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    @Import(name="timeCreated")
    private @Nullable Output<String> timeCreated;

    /**
     * @return The date and time the volume backup policy was assigned to the volume. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    public Optional<Output<String>> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    private VolumeBackupPolicyAssignmentState() {}

    private VolumeBackupPolicyAssignmentState(VolumeBackupPolicyAssignmentState $) {
        this.assetId = $.assetId;
        this.policyId = $.policyId;
        this.timeCreated = $.timeCreated;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(VolumeBackupPolicyAssignmentState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private VolumeBackupPolicyAssignmentState $;

        public Builder() {
            $ = new VolumeBackupPolicyAssignmentState();
        }

        public Builder(VolumeBackupPolicyAssignmentState defaults) {
            $ = new VolumeBackupPolicyAssignmentState(Objects.requireNonNull(defaults));
        }

        /**
         * @param assetId The OCID of the volume to assign the policy to.
         * 
         * @return builder
         * 
         */
        public Builder assetId(@Nullable Output<String> assetId) {
            $.assetId = assetId;
            return this;
        }

        /**
         * @param assetId The OCID of the volume to assign the policy to.
         * 
         * @return builder
         * 
         */
        public Builder assetId(String assetId) {
            return assetId(Output.of(assetId));
        }

        /**
         * @param policyId The OCID of the volume backup policy to assign to the volume.
         * 
         * @return builder
         * 
         */
        public Builder policyId(@Nullable Output<String> policyId) {
            $.policyId = policyId;
            return this;
        }

        /**
         * @param policyId The OCID of the volume backup policy to assign to the volume.
         * 
         * @return builder
         * 
         */
        public Builder policyId(String policyId) {
            return policyId(Output.of(policyId));
        }

        /**
         * @param timeCreated The date and time the volume backup policy was assigned to the volume. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(@Nullable Output<String> timeCreated) {
            $.timeCreated = timeCreated;
            return this;
        }

        /**
         * @param timeCreated The date and time the volume backup policy was assigned to the volume. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(String timeCreated) {
            return timeCreated(Output.of(timeCreated));
        }

        public VolumeBackupPolicyAssignmentState build() {
            return $;
        }
    }

}
