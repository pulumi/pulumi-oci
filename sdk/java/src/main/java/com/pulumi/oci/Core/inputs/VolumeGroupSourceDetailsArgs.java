// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class VolumeGroupSourceDetailsArgs extends com.pulumi.resources.ResourceArgs {

    public static final VolumeGroupSourceDetailsArgs Empty = new VolumeGroupSourceDetailsArgs();

    /**
     * The type can be one of these values: `volumeGroupBackupId`, `volumeGroupId`, `volumeGroupReplicaId`, `volumeIds`
     * 
     */
    @Import(name="type", required=true)
    private Output<String> type;

    /**
     * @return The type can be one of these values: `volumeGroupBackupId`, `volumeGroupId`, `volumeGroupReplicaId`, `volumeIds`
     * 
     */
    public Output<String> type() {
        return this.type;
    }

    /**
     * The OCID of the volume group backup to restore from.
     * 
     */
    @Import(name="volumeGroupBackupId")
    private @Nullable Output<String> volumeGroupBackupId;

    /**
     * @return The OCID of the volume group backup to restore from.
     * 
     */
    public Optional<Output<String>> volumeGroupBackupId() {
        return Optional.ofNullable(this.volumeGroupBackupId);
    }

    /**
     * The OCID of the volume group to clone from.
     * 
     */
    @Import(name="volumeGroupId")
    private @Nullable Output<String> volumeGroupId;

    /**
     * @return The OCID of the volume group to clone from.
     * 
     */
    public Optional<Output<String>> volumeGroupId() {
        return Optional.ofNullable(this.volumeGroupId);
    }

    /**
     * The OCID of the volume group replica.
     * 
     */
    @Import(name="volumeGroupReplicaId")
    private @Nullable Output<String> volumeGroupReplicaId;

    /**
     * @return The OCID of the volume group replica.
     * 
     */
    public Optional<Output<String>> volumeGroupReplicaId() {
        return Optional.ofNullable(this.volumeGroupReplicaId);
    }

    /**
     * OCIDs for the volumes used to create this volume group.
     * 
     */
    @Import(name="volumeIds")
    private @Nullable Output<List<String>> volumeIds;

    /**
     * @return OCIDs for the volumes used to create this volume group.
     * 
     */
    public Optional<Output<List<String>>> volumeIds() {
        return Optional.ofNullable(this.volumeIds);
    }

    private VolumeGroupSourceDetailsArgs() {}

    private VolumeGroupSourceDetailsArgs(VolumeGroupSourceDetailsArgs $) {
        this.type = $.type;
        this.volumeGroupBackupId = $.volumeGroupBackupId;
        this.volumeGroupId = $.volumeGroupId;
        this.volumeGroupReplicaId = $.volumeGroupReplicaId;
        this.volumeIds = $.volumeIds;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(VolumeGroupSourceDetailsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private VolumeGroupSourceDetailsArgs $;

        public Builder() {
            $ = new VolumeGroupSourceDetailsArgs();
        }

        public Builder(VolumeGroupSourceDetailsArgs defaults) {
            $ = new VolumeGroupSourceDetailsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param type The type can be one of these values: `volumeGroupBackupId`, `volumeGroupId`, `volumeGroupReplicaId`, `volumeIds`
         * 
         * @return builder
         * 
         */
        public Builder type(Output<String> type) {
            $.type = type;
            return this;
        }

        /**
         * @param type The type can be one of these values: `volumeGroupBackupId`, `volumeGroupId`, `volumeGroupReplicaId`, `volumeIds`
         * 
         * @return builder
         * 
         */
        public Builder type(String type) {
            return type(Output.of(type));
        }

        /**
         * @param volumeGroupBackupId The OCID of the volume group backup to restore from.
         * 
         * @return builder
         * 
         */
        public Builder volumeGroupBackupId(@Nullable Output<String> volumeGroupBackupId) {
            $.volumeGroupBackupId = volumeGroupBackupId;
            return this;
        }

        /**
         * @param volumeGroupBackupId The OCID of the volume group backup to restore from.
         * 
         * @return builder
         * 
         */
        public Builder volumeGroupBackupId(String volumeGroupBackupId) {
            return volumeGroupBackupId(Output.of(volumeGroupBackupId));
        }

        /**
         * @param volumeGroupId The OCID of the volume group to clone from.
         * 
         * @return builder
         * 
         */
        public Builder volumeGroupId(@Nullable Output<String> volumeGroupId) {
            $.volumeGroupId = volumeGroupId;
            return this;
        }

        /**
         * @param volumeGroupId The OCID of the volume group to clone from.
         * 
         * @return builder
         * 
         */
        public Builder volumeGroupId(String volumeGroupId) {
            return volumeGroupId(Output.of(volumeGroupId));
        }

        /**
         * @param volumeGroupReplicaId The OCID of the volume group replica.
         * 
         * @return builder
         * 
         */
        public Builder volumeGroupReplicaId(@Nullable Output<String> volumeGroupReplicaId) {
            $.volumeGroupReplicaId = volumeGroupReplicaId;
            return this;
        }

        /**
         * @param volumeGroupReplicaId The OCID of the volume group replica.
         * 
         * @return builder
         * 
         */
        public Builder volumeGroupReplicaId(String volumeGroupReplicaId) {
            return volumeGroupReplicaId(Output.of(volumeGroupReplicaId));
        }

        /**
         * @param volumeIds OCIDs for the volumes used to create this volume group.
         * 
         * @return builder
         * 
         */
        public Builder volumeIds(@Nullable Output<List<String>> volumeIds) {
            $.volumeIds = volumeIds;
            return this;
        }

        /**
         * @param volumeIds OCIDs for the volumes used to create this volume group.
         * 
         * @return builder
         * 
         */
        public Builder volumeIds(List<String> volumeIds) {
            return volumeIds(Output.of(volumeIds));
        }

        /**
         * @param volumeIds OCIDs for the volumes used to create this volume group.
         * 
         * @return builder
         * 
         */
        public Builder volumeIds(String... volumeIds) {
            return volumeIds(List.of(volumeIds));
        }

        public VolumeGroupSourceDetailsArgs build() {
            if ($.type == null) {
                throw new MissingRequiredPropertyException("VolumeGroupSourceDetailsArgs", "type");
            }
            return $;
        }
    }

}
