// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetVolumesVolumeSourceDetail {
    /**
     * @return (Applicable when type=volumeBackupDelta) Block size in bytes to be considered while performing volume restore. The value must be a power of 2; ranging from 4KB (4096 bytes) to 1MB (1048576 bytes). If omitted, defaults to 4,096 bytes (4 KiB).
     * 
     */
    private String changeBlockSizeInBytes;
    /**
     * @return (Required when type=volumeBackupDelta) The OCID of the first volume backup.
     * 
     */
    private String firstBackupId;
    /**
     * @return (Required when type=blockVolumeReplica | volume | volumeBackup) The OCID of the block volume replica.
     * 
     */
    private String id;
    /**
     * @return (Required when type=volumeBackupDelta) The OCID of the second volume backup.
     * 
     */
    private String secondBackupId;
    /**
     * @return (Required) The type can be one of these values: `blockVolumeReplica`, `volume`, `volumeBackup`, `volumeBackupDelta`
     * 
     */
    private String type;

    private GetVolumesVolumeSourceDetail() {}
    /**
     * @return (Applicable when type=volumeBackupDelta) Block size in bytes to be considered while performing volume restore. The value must be a power of 2; ranging from 4KB (4096 bytes) to 1MB (1048576 bytes). If omitted, defaults to 4,096 bytes (4 KiB).
     * 
     */
    public String changeBlockSizeInBytes() {
        return this.changeBlockSizeInBytes;
    }
    /**
     * @return (Required when type=volumeBackupDelta) The OCID of the first volume backup.
     * 
     */
    public String firstBackupId() {
        return this.firstBackupId;
    }
    /**
     * @return (Required when type=blockVolumeReplica | volume | volumeBackup) The OCID of the block volume replica.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return (Required when type=volumeBackupDelta) The OCID of the second volume backup.
     * 
     */
    public String secondBackupId() {
        return this.secondBackupId;
    }
    /**
     * @return (Required) The type can be one of these values: `blockVolumeReplica`, `volume`, `volumeBackup`, `volumeBackupDelta`
     * 
     */
    public String type() {
        return this.type;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetVolumesVolumeSourceDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String changeBlockSizeInBytes;
        private String firstBackupId;
        private String id;
        private String secondBackupId;
        private String type;
        public Builder() {}
        public Builder(GetVolumesVolumeSourceDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.changeBlockSizeInBytes = defaults.changeBlockSizeInBytes;
    	      this.firstBackupId = defaults.firstBackupId;
    	      this.id = defaults.id;
    	      this.secondBackupId = defaults.secondBackupId;
    	      this.type = defaults.type;
        }

        @CustomType.Setter
        public Builder changeBlockSizeInBytes(String changeBlockSizeInBytes) {
            if (changeBlockSizeInBytes == null) {
              throw new MissingRequiredPropertyException("GetVolumesVolumeSourceDetail", "changeBlockSizeInBytes");
            }
            this.changeBlockSizeInBytes = changeBlockSizeInBytes;
            return this;
        }
        @CustomType.Setter
        public Builder firstBackupId(String firstBackupId) {
            if (firstBackupId == null) {
              throw new MissingRequiredPropertyException("GetVolumesVolumeSourceDetail", "firstBackupId");
            }
            this.firstBackupId = firstBackupId;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetVolumesVolumeSourceDetail", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder secondBackupId(String secondBackupId) {
            if (secondBackupId == null) {
              throw new MissingRequiredPropertyException("GetVolumesVolumeSourceDetail", "secondBackupId");
            }
            this.secondBackupId = secondBackupId;
            return this;
        }
        @CustomType.Setter
        public Builder type(String type) {
            if (type == null) {
              throw new MissingRequiredPropertyException("GetVolumesVolumeSourceDetail", "type");
            }
            this.type = type;
            return this;
        }
        public GetVolumesVolumeSourceDetail build() {
            final var _resultValue = new GetVolumesVolumeSourceDetail();
            _resultValue.changeBlockSizeInBytes = changeBlockSizeInBytes;
            _resultValue.firstBackupId = firstBackupId;
            _resultValue.id = id;
            _resultValue.secondBackupId = secondBackupId;
            _resultValue.type = type;
            return _resultValue;
        }
    }
}
