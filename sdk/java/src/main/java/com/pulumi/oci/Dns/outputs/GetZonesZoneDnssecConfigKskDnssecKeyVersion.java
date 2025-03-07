// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Dns.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Dns.outputs.GetZonesZoneDnssecConfigKskDnssecKeyVersionDsData;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetZonesZoneDnssecConfigKskDnssecKeyVersion {
    /**
     * @return The signing algorithm used for the key.
     * 
     */
    private String algorithm;
    /**
     * @return An array of data for DS records corresponding with this key version. An entry will exist for each supported DS digest algorithm.
     * 
     */
    private List<GetZonesZoneDnssecConfigKskDnssecKeyVersionDsData> dsDatas;
    /**
     * @return The key tag associated with the `DnssecKeyVersion`. This key tag will be present in the RRSIG and DS records associated with the key material for this `DnssecKeyVersion`. For more information about key tags, see [RFC 4034](https://tools.ietf.org/html/rfc4034).
     * 
     */
    private Integer keyTag;
    /**
     * @return The length of the corresponding private key in bytes, expressed as an integer.
     * 
     */
    private Integer lengthInBytes;
    /**
     * @return When populated, this is the UUID of the `DnssecKeyVersion` that this `DnssecKeyVersion` will replace or has replaced.
     * 
     */
    private String predecessorDnssecKeyVersionUuid;
    /**
     * @return When populated, this is the UUID of the `DnssecKeyVersion` that will replace, or has replaced, this `DnssecKeyVersion`.
     * 
     */
    private String successorDnssecKeyVersionUuid;
    /**
     * @return The date and time the key version went, or will go, active, expressed in RFC 3339 timestamp format. This is when the key material will be used to generate RRSIGs.
     * 
     */
    private String timeActivated;
    /**
     * @return The date and time the resource was created in &#34;YYYY-MM-ddThh:mm:ssZ&#34; format with a Z offset, as defined by RFC 3339.
     * 
     */
    private String timeCreated;
    /**
     * @return The date and time at which the recommended key version publication/activation lifetime ends, expressed in RFC 3339 timestamp format. This is when the corresponding DNSKEY should no longer exist in zone contents and no longer be used to generate RRSIGs. For a key sigining key (KSK), if `PromoteZoneDnssecKeyVersion` has not been called on this `DnssecKeyVersion`&#39;s successor then it will remain active for arbitrarily long past its recommended lifetime. This prevents service disruption at the potential increased risk of key compromise.
     * 
     */
    private String timeExpired;
    /**
     * @return The date and time the key version went, or will go, inactive, expressed in RFC 3339 timestamp format. This is when the key material will no longer be used to generate RRSIGs. For a key signing key (KSK) `DnssecKeyVersion`, this is populated after `PromoteZoneDnssecKeyVersion` has been called on its successor `DnssecKeyVersion`.
     * 
     */
    private String timeInactivated;
    /**
     * @return The date and time the key version was promoted expressed in RFC 3339 timestamp format.
     * 
     */
    private String timePromoted;
    /**
     * @return The date and time the key version was, or will be, published, expressed in RFC 3339 timestamp format. This is when the zone contents will include a DNSKEY record corresponding to the key material.
     * 
     */
    private String timePublished;
    /**
     * @return The date and time the key version was, or will be, unpublished, expressed in RFC 3339 timestamp format. This is when the corresponding DNSKEY will be removed from zone contents. For a key signing key (KSK) `DnssecKeyVersion`, this is populated after `PromoteZoneDnssecKeyVersion` has been called on its successor `DnssecKeyVersion`.
     * 
     */
    private String timeUnpublished;
    /**
     * @return The UUID of the `DnssecKeyVersion`.
     * 
     */
    private String uuid;

    private GetZonesZoneDnssecConfigKskDnssecKeyVersion() {}
    /**
     * @return The signing algorithm used for the key.
     * 
     */
    public String algorithm() {
        return this.algorithm;
    }
    /**
     * @return An array of data for DS records corresponding with this key version. An entry will exist for each supported DS digest algorithm.
     * 
     */
    public List<GetZonesZoneDnssecConfigKskDnssecKeyVersionDsData> dsDatas() {
        return this.dsDatas;
    }
    /**
     * @return The key tag associated with the `DnssecKeyVersion`. This key tag will be present in the RRSIG and DS records associated with the key material for this `DnssecKeyVersion`. For more information about key tags, see [RFC 4034](https://tools.ietf.org/html/rfc4034).
     * 
     */
    public Integer keyTag() {
        return this.keyTag;
    }
    /**
     * @return The length of the corresponding private key in bytes, expressed as an integer.
     * 
     */
    public Integer lengthInBytes() {
        return this.lengthInBytes;
    }
    /**
     * @return When populated, this is the UUID of the `DnssecKeyVersion` that this `DnssecKeyVersion` will replace or has replaced.
     * 
     */
    public String predecessorDnssecKeyVersionUuid() {
        return this.predecessorDnssecKeyVersionUuid;
    }
    /**
     * @return When populated, this is the UUID of the `DnssecKeyVersion` that will replace, or has replaced, this `DnssecKeyVersion`.
     * 
     */
    public String successorDnssecKeyVersionUuid() {
        return this.successorDnssecKeyVersionUuid;
    }
    /**
     * @return The date and time the key version went, or will go, active, expressed in RFC 3339 timestamp format. This is when the key material will be used to generate RRSIGs.
     * 
     */
    public String timeActivated() {
        return this.timeActivated;
    }
    /**
     * @return The date and time the resource was created in &#34;YYYY-MM-ddThh:mm:ssZ&#34; format with a Z offset, as defined by RFC 3339.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The date and time at which the recommended key version publication/activation lifetime ends, expressed in RFC 3339 timestamp format. This is when the corresponding DNSKEY should no longer exist in zone contents and no longer be used to generate RRSIGs. For a key sigining key (KSK), if `PromoteZoneDnssecKeyVersion` has not been called on this `DnssecKeyVersion`&#39;s successor then it will remain active for arbitrarily long past its recommended lifetime. This prevents service disruption at the potential increased risk of key compromise.
     * 
     */
    public String timeExpired() {
        return this.timeExpired;
    }
    /**
     * @return The date and time the key version went, or will go, inactive, expressed in RFC 3339 timestamp format. This is when the key material will no longer be used to generate RRSIGs. For a key signing key (KSK) `DnssecKeyVersion`, this is populated after `PromoteZoneDnssecKeyVersion` has been called on its successor `DnssecKeyVersion`.
     * 
     */
    public String timeInactivated() {
        return this.timeInactivated;
    }
    /**
     * @return The date and time the key version was promoted expressed in RFC 3339 timestamp format.
     * 
     */
    public String timePromoted() {
        return this.timePromoted;
    }
    /**
     * @return The date and time the key version was, or will be, published, expressed in RFC 3339 timestamp format. This is when the zone contents will include a DNSKEY record corresponding to the key material.
     * 
     */
    public String timePublished() {
        return this.timePublished;
    }
    /**
     * @return The date and time the key version was, or will be, unpublished, expressed in RFC 3339 timestamp format. This is when the corresponding DNSKEY will be removed from zone contents. For a key signing key (KSK) `DnssecKeyVersion`, this is populated after `PromoteZoneDnssecKeyVersion` has been called on its successor `DnssecKeyVersion`.
     * 
     */
    public String timeUnpublished() {
        return this.timeUnpublished;
    }
    /**
     * @return The UUID of the `DnssecKeyVersion`.
     * 
     */
    public String uuid() {
        return this.uuid;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetZonesZoneDnssecConfigKskDnssecKeyVersion defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String algorithm;
        private List<GetZonesZoneDnssecConfigKskDnssecKeyVersionDsData> dsDatas;
        private Integer keyTag;
        private Integer lengthInBytes;
        private String predecessorDnssecKeyVersionUuid;
        private String successorDnssecKeyVersionUuid;
        private String timeActivated;
        private String timeCreated;
        private String timeExpired;
        private String timeInactivated;
        private String timePromoted;
        private String timePublished;
        private String timeUnpublished;
        private String uuid;
        public Builder() {}
        public Builder(GetZonesZoneDnssecConfigKskDnssecKeyVersion defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.algorithm = defaults.algorithm;
    	      this.dsDatas = defaults.dsDatas;
    	      this.keyTag = defaults.keyTag;
    	      this.lengthInBytes = defaults.lengthInBytes;
    	      this.predecessorDnssecKeyVersionUuid = defaults.predecessorDnssecKeyVersionUuid;
    	      this.successorDnssecKeyVersionUuid = defaults.successorDnssecKeyVersionUuid;
    	      this.timeActivated = defaults.timeActivated;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeExpired = defaults.timeExpired;
    	      this.timeInactivated = defaults.timeInactivated;
    	      this.timePromoted = defaults.timePromoted;
    	      this.timePublished = defaults.timePublished;
    	      this.timeUnpublished = defaults.timeUnpublished;
    	      this.uuid = defaults.uuid;
        }

        @CustomType.Setter
        public Builder algorithm(String algorithm) {
            if (algorithm == null) {
              throw new MissingRequiredPropertyException("GetZonesZoneDnssecConfigKskDnssecKeyVersion", "algorithm");
            }
            this.algorithm = algorithm;
            return this;
        }
        @CustomType.Setter
        public Builder dsDatas(List<GetZonesZoneDnssecConfigKskDnssecKeyVersionDsData> dsDatas) {
            if (dsDatas == null) {
              throw new MissingRequiredPropertyException("GetZonesZoneDnssecConfigKskDnssecKeyVersion", "dsDatas");
            }
            this.dsDatas = dsDatas;
            return this;
        }
        public Builder dsDatas(GetZonesZoneDnssecConfigKskDnssecKeyVersionDsData... dsDatas) {
            return dsDatas(List.of(dsDatas));
        }
        @CustomType.Setter
        public Builder keyTag(Integer keyTag) {
            if (keyTag == null) {
              throw new MissingRequiredPropertyException("GetZonesZoneDnssecConfigKskDnssecKeyVersion", "keyTag");
            }
            this.keyTag = keyTag;
            return this;
        }
        @CustomType.Setter
        public Builder lengthInBytes(Integer lengthInBytes) {
            if (lengthInBytes == null) {
              throw new MissingRequiredPropertyException("GetZonesZoneDnssecConfigKskDnssecKeyVersion", "lengthInBytes");
            }
            this.lengthInBytes = lengthInBytes;
            return this;
        }
        @CustomType.Setter
        public Builder predecessorDnssecKeyVersionUuid(String predecessorDnssecKeyVersionUuid) {
            if (predecessorDnssecKeyVersionUuid == null) {
              throw new MissingRequiredPropertyException("GetZonesZoneDnssecConfigKskDnssecKeyVersion", "predecessorDnssecKeyVersionUuid");
            }
            this.predecessorDnssecKeyVersionUuid = predecessorDnssecKeyVersionUuid;
            return this;
        }
        @CustomType.Setter
        public Builder successorDnssecKeyVersionUuid(String successorDnssecKeyVersionUuid) {
            if (successorDnssecKeyVersionUuid == null) {
              throw new MissingRequiredPropertyException("GetZonesZoneDnssecConfigKskDnssecKeyVersion", "successorDnssecKeyVersionUuid");
            }
            this.successorDnssecKeyVersionUuid = successorDnssecKeyVersionUuid;
            return this;
        }
        @CustomType.Setter
        public Builder timeActivated(String timeActivated) {
            if (timeActivated == null) {
              throw new MissingRequiredPropertyException("GetZonesZoneDnssecConfigKskDnssecKeyVersion", "timeActivated");
            }
            this.timeActivated = timeActivated;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetZonesZoneDnssecConfigKskDnssecKeyVersion", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder timeExpired(String timeExpired) {
            if (timeExpired == null) {
              throw new MissingRequiredPropertyException("GetZonesZoneDnssecConfigKskDnssecKeyVersion", "timeExpired");
            }
            this.timeExpired = timeExpired;
            return this;
        }
        @CustomType.Setter
        public Builder timeInactivated(String timeInactivated) {
            if (timeInactivated == null) {
              throw new MissingRequiredPropertyException("GetZonesZoneDnssecConfigKskDnssecKeyVersion", "timeInactivated");
            }
            this.timeInactivated = timeInactivated;
            return this;
        }
        @CustomType.Setter
        public Builder timePromoted(String timePromoted) {
            if (timePromoted == null) {
              throw new MissingRequiredPropertyException("GetZonesZoneDnssecConfigKskDnssecKeyVersion", "timePromoted");
            }
            this.timePromoted = timePromoted;
            return this;
        }
        @CustomType.Setter
        public Builder timePublished(String timePublished) {
            if (timePublished == null) {
              throw new MissingRequiredPropertyException("GetZonesZoneDnssecConfigKskDnssecKeyVersion", "timePublished");
            }
            this.timePublished = timePublished;
            return this;
        }
        @CustomType.Setter
        public Builder timeUnpublished(String timeUnpublished) {
            if (timeUnpublished == null) {
              throw new MissingRequiredPropertyException("GetZonesZoneDnssecConfigKskDnssecKeyVersion", "timeUnpublished");
            }
            this.timeUnpublished = timeUnpublished;
            return this;
        }
        @CustomType.Setter
        public Builder uuid(String uuid) {
            if (uuid == null) {
              throw new MissingRequiredPropertyException("GetZonesZoneDnssecConfigKskDnssecKeyVersion", "uuid");
            }
            this.uuid = uuid;
            return this;
        }
        public GetZonesZoneDnssecConfigKskDnssecKeyVersion build() {
            final var _resultValue = new GetZonesZoneDnssecConfigKskDnssecKeyVersion();
            _resultValue.algorithm = algorithm;
            _resultValue.dsDatas = dsDatas;
            _resultValue.keyTag = keyTag;
            _resultValue.lengthInBytes = lengthInBytes;
            _resultValue.predecessorDnssecKeyVersionUuid = predecessorDnssecKeyVersionUuid;
            _resultValue.successorDnssecKeyVersionUuid = successorDnssecKeyVersionUuid;
            _resultValue.timeActivated = timeActivated;
            _resultValue.timeCreated = timeCreated;
            _resultValue.timeExpired = timeExpired;
            _resultValue.timeInactivated = timeInactivated;
            _resultValue.timePromoted = timePromoted;
            _resultValue.timePublished = timePublished;
            _resultValue.timeUnpublished = timeUnpublished;
            _resultValue.uuid = uuid;
            return _resultValue;
        }
    }
}
