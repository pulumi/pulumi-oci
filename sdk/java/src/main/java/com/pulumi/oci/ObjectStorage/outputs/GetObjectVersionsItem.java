// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ObjectStorage.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetObjectVersionsItem {
    /**
     * @return Archival state of an object. This field is set only for objects in Archive tier.
     * 
     */
    private String archivalState;
    /**
     * @return The current entity tag (ETag) for the object.
     * 
     */
    private String etag;
    /**
     * @return This flag will indicate if the version is deleted or not.
     * 
     */
    private Boolean isDeleteMarker;
    /**
     * @return Base64-encoded MD5 hash of the object data.
     * 
     */
    private String md5;
    /**
     * @return The name of the object. Avoid entering confidential information. Example: test/object1.log
     * 
     */
    private String name;
    /**
     * @return Size of the object in bytes.
     * 
     */
    private String size;
    /**
     * @return The storage tier that the object is stored in.
     * 
     */
    private String storageTier;
    /**
     * @return The date and time the object was created, as described in [RFC 2616](https://tools.ietf.org/html/rfc2616#section-14.29).
     * 
     */
    private String timeCreated;
    /**
     * @return The date and time the object was modified, as described in [RFC 2616](https://tools.ietf.org/rfc/rfc2616#section-14.29).
     * 
     */
    private String timeModified;
    /**
     * @return VersionId of the object.
     * 
     */
    private String versionId;

    private GetObjectVersionsItem() {}
    /**
     * @return Archival state of an object. This field is set only for objects in Archive tier.
     * 
     */
    public String archivalState() {
        return this.archivalState;
    }
    /**
     * @return The current entity tag (ETag) for the object.
     * 
     */
    public String etag() {
        return this.etag;
    }
    /**
     * @return This flag will indicate if the version is deleted or not.
     * 
     */
    public Boolean isDeleteMarker() {
        return this.isDeleteMarker;
    }
    /**
     * @return Base64-encoded MD5 hash of the object data.
     * 
     */
    public String md5() {
        return this.md5;
    }
    /**
     * @return The name of the object. Avoid entering confidential information. Example: test/object1.log
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return Size of the object in bytes.
     * 
     */
    public String size() {
        return this.size;
    }
    /**
     * @return The storage tier that the object is stored in.
     * 
     */
    public String storageTier() {
        return this.storageTier;
    }
    /**
     * @return The date and time the object was created, as described in [RFC 2616](https://tools.ietf.org/html/rfc2616#section-14.29).
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The date and time the object was modified, as described in [RFC 2616](https://tools.ietf.org/rfc/rfc2616#section-14.29).
     * 
     */
    public String timeModified() {
        return this.timeModified;
    }
    /**
     * @return VersionId of the object.
     * 
     */
    public String versionId() {
        return this.versionId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetObjectVersionsItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String archivalState;
        private String etag;
        private Boolean isDeleteMarker;
        private String md5;
        private String name;
        private String size;
        private String storageTier;
        private String timeCreated;
        private String timeModified;
        private String versionId;
        public Builder() {}
        public Builder(GetObjectVersionsItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.archivalState = defaults.archivalState;
    	      this.etag = defaults.etag;
    	      this.isDeleteMarker = defaults.isDeleteMarker;
    	      this.md5 = defaults.md5;
    	      this.name = defaults.name;
    	      this.size = defaults.size;
    	      this.storageTier = defaults.storageTier;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeModified = defaults.timeModified;
    	      this.versionId = defaults.versionId;
        }

        @CustomType.Setter
        public Builder archivalState(String archivalState) {
            if (archivalState == null) {
              throw new MissingRequiredPropertyException("GetObjectVersionsItem", "archivalState");
            }
            this.archivalState = archivalState;
            return this;
        }
        @CustomType.Setter
        public Builder etag(String etag) {
            if (etag == null) {
              throw new MissingRequiredPropertyException("GetObjectVersionsItem", "etag");
            }
            this.etag = etag;
            return this;
        }
        @CustomType.Setter
        public Builder isDeleteMarker(Boolean isDeleteMarker) {
            if (isDeleteMarker == null) {
              throw new MissingRequiredPropertyException("GetObjectVersionsItem", "isDeleteMarker");
            }
            this.isDeleteMarker = isDeleteMarker;
            return this;
        }
        @CustomType.Setter
        public Builder md5(String md5) {
            if (md5 == null) {
              throw new MissingRequiredPropertyException("GetObjectVersionsItem", "md5");
            }
            this.md5 = md5;
            return this;
        }
        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("GetObjectVersionsItem", "name");
            }
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder size(String size) {
            if (size == null) {
              throw new MissingRequiredPropertyException("GetObjectVersionsItem", "size");
            }
            this.size = size;
            return this;
        }
        @CustomType.Setter
        public Builder storageTier(String storageTier) {
            if (storageTier == null) {
              throw new MissingRequiredPropertyException("GetObjectVersionsItem", "storageTier");
            }
            this.storageTier = storageTier;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetObjectVersionsItem", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder timeModified(String timeModified) {
            if (timeModified == null) {
              throw new MissingRequiredPropertyException("GetObjectVersionsItem", "timeModified");
            }
            this.timeModified = timeModified;
            return this;
        }
        @CustomType.Setter
        public Builder versionId(String versionId) {
            if (versionId == null) {
              throw new MissingRequiredPropertyException("GetObjectVersionsItem", "versionId");
            }
            this.versionId = versionId;
            return this;
        }
        public GetObjectVersionsItem build() {
            final var _resultValue = new GetObjectVersionsItem();
            _resultValue.archivalState = archivalState;
            _resultValue.etag = etag;
            _resultValue.isDeleteMarker = isDeleteMarker;
            _resultValue.md5 = md5;
            _resultValue.name = name;
            _resultValue.size = size;
            _resultValue.storageTier = storageTier;
            _resultValue.timeCreated = timeCreated;
            _resultValue.timeModified = timeModified;
            _resultValue.versionId = versionId;
            return _resultValue;
        }
    }
}
