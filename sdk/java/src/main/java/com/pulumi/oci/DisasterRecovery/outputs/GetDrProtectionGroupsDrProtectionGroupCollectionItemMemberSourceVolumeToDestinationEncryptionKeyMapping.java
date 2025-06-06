// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DisasterRecovery.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DisasterRecovery.outputs.GetDrProtectionGroupsDrProtectionGroupCollectionItemMemberSourceVolumeToDestinationEncryptionKeyMappingDestinationEncryptionKey;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDrProtectionGroupsDrProtectionGroupCollectionItemMemberSourceVolumeToDestinationEncryptionKeyMapping {
    /**
     * @return The OCID of a vault and customer-managed encryption key in the destination region.
     * 
     */
    private List<GetDrProtectionGroupsDrProtectionGroupCollectionItemMemberSourceVolumeToDestinationEncryptionKeyMappingDestinationEncryptionKey> destinationEncryptionKeys;
    /**
     * @return The OCID of the source boot volume or block volume.  Example: `ocid1.volume.oc1..uniqueID`
     * 
     */
    private String sourceVolumeId;

    private GetDrProtectionGroupsDrProtectionGroupCollectionItemMemberSourceVolumeToDestinationEncryptionKeyMapping() {}
    /**
     * @return The OCID of a vault and customer-managed encryption key in the destination region.
     * 
     */
    public List<GetDrProtectionGroupsDrProtectionGroupCollectionItemMemberSourceVolumeToDestinationEncryptionKeyMappingDestinationEncryptionKey> destinationEncryptionKeys() {
        return this.destinationEncryptionKeys;
    }
    /**
     * @return The OCID of the source boot volume or block volume.  Example: `ocid1.volume.oc1..uniqueID`
     * 
     */
    public String sourceVolumeId() {
        return this.sourceVolumeId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDrProtectionGroupsDrProtectionGroupCollectionItemMemberSourceVolumeToDestinationEncryptionKeyMapping defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetDrProtectionGroupsDrProtectionGroupCollectionItemMemberSourceVolumeToDestinationEncryptionKeyMappingDestinationEncryptionKey> destinationEncryptionKeys;
        private String sourceVolumeId;
        public Builder() {}
        public Builder(GetDrProtectionGroupsDrProtectionGroupCollectionItemMemberSourceVolumeToDestinationEncryptionKeyMapping defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.destinationEncryptionKeys = defaults.destinationEncryptionKeys;
    	      this.sourceVolumeId = defaults.sourceVolumeId;
        }

        @CustomType.Setter
        public Builder destinationEncryptionKeys(List<GetDrProtectionGroupsDrProtectionGroupCollectionItemMemberSourceVolumeToDestinationEncryptionKeyMappingDestinationEncryptionKey> destinationEncryptionKeys) {
            if (destinationEncryptionKeys == null) {
              throw new MissingRequiredPropertyException("GetDrProtectionGroupsDrProtectionGroupCollectionItemMemberSourceVolumeToDestinationEncryptionKeyMapping", "destinationEncryptionKeys");
            }
            this.destinationEncryptionKeys = destinationEncryptionKeys;
            return this;
        }
        public Builder destinationEncryptionKeys(GetDrProtectionGroupsDrProtectionGroupCollectionItemMemberSourceVolumeToDestinationEncryptionKeyMappingDestinationEncryptionKey... destinationEncryptionKeys) {
            return destinationEncryptionKeys(List.of(destinationEncryptionKeys));
        }
        @CustomType.Setter
        public Builder sourceVolumeId(String sourceVolumeId) {
            if (sourceVolumeId == null) {
              throw new MissingRequiredPropertyException("GetDrProtectionGroupsDrProtectionGroupCollectionItemMemberSourceVolumeToDestinationEncryptionKeyMapping", "sourceVolumeId");
            }
            this.sourceVolumeId = sourceVolumeId;
            return this;
        }
        public GetDrProtectionGroupsDrProtectionGroupCollectionItemMemberSourceVolumeToDestinationEncryptionKeyMapping build() {
            final var _resultValue = new GetDrProtectionGroupsDrProtectionGroupCollectionItemMemberSourceVolumeToDestinationEncryptionKeyMapping();
            _resultValue.destinationEncryptionKeys = destinationEncryptionKeys;
            _resultValue.sourceVolumeId = sourceVolumeId;
            return _resultValue;
        }
    }
}
