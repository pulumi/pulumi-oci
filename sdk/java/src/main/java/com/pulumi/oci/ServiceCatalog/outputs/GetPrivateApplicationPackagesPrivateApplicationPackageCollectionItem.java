// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ServiceCatalog.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetPrivateApplicationPackagesPrivateApplicationPackageCollectionItem {
    private String contentUrl;
    /**
     * @return Exact match name filter.
     * 
     */
    private String displayName;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the private application package.
     * 
     */
    private String id;
    private String mimeType;
    /**
     * @return Name of the package type. If multiple package types are provided, then any resource with one or more matching package types will be returned.
     * 
     */
    private String packageType;
    /**
     * @return The unique identifier for the private application.
     * 
     */
    private String privateApplicationId;
    /**
     * @return The date and time the private application package was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2021-05-27T21:10:29.600Z`
     * 
     */
    private String timeCreated;
    /**
     * @return The package version.
     * 
     */
    private String version;

    private GetPrivateApplicationPackagesPrivateApplicationPackageCollectionItem() {}
    public String contentUrl() {
        return this.contentUrl;
    }
    /**
     * @return Exact match name filter.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the private application package.
     * 
     */
    public String id() {
        return this.id;
    }
    public String mimeType() {
        return this.mimeType;
    }
    /**
     * @return Name of the package type. If multiple package types are provided, then any resource with one or more matching package types will be returned.
     * 
     */
    public String packageType() {
        return this.packageType;
    }
    /**
     * @return The unique identifier for the private application.
     * 
     */
    public String privateApplicationId() {
        return this.privateApplicationId;
    }
    /**
     * @return The date and time the private application package was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2021-05-27T21:10:29.600Z`
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The package version.
     * 
     */
    public String version() {
        return this.version;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetPrivateApplicationPackagesPrivateApplicationPackageCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String contentUrl;
        private String displayName;
        private String id;
        private String mimeType;
        private String packageType;
        private String privateApplicationId;
        private String timeCreated;
        private String version;
        public Builder() {}
        public Builder(GetPrivateApplicationPackagesPrivateApplicationPackageCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.contentUrl = defaults.contentUrl;
    	      this.displayName = defaults.displayName;
    	      this.id = defaults.id;
    	      this.mimeType = defaults.mimeType;
    	      this.packageType = defaults.packageType;
    	      this.privateApplicationId = defaults.privateApplicationId;
    	      this.timeCreated = defaults.timeCreated;
    	      this.version = defaults.version;
        }

        @CustomType.Setter
        public Builder contentUrl(String contentUrl) {
            if (contentUrl == null) {
              throw new MissingRequiredPropertyException("GetPrivateApplicationPackagesPrivateApplicationPackageCollectionItem", "contentUrl");
            }
            this.contentUrl = contentUrl;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetPrivateApplicationPackagesPrivateApplicationPackageCollectionItem", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetPrivateApplicationPackagesPrivateApplicationPackageCollectionItem", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder mimeType(String mimeType) {
            if (mimeType == null) {
              throw new MissingRequiredPropertyException("GetPrivateApplicationPackagesPrivateApplicationPackageCollectionItem", "mimeType");
            }
            this.mimeType = mimeType;
            return this;
        }
        @CustomType.Setter
        public Builder packageType(String packageType) {
            if (packageType == null) {
              throw new MissingRequiredPropertyException("GetPrivateApplicationPackagesPrivateApplicationPackageCollectionItem", "packageType");
            }
            this.packageType = packageType;
            return this;
        }
        @CustomType.Setter
        public Builder privateApplicationId(String privateApplicationId) {
            if (privateApplicationId == null) {
              throw new MissingRequiredPropertyException("GetPrivateApplicationPackagesPrivateApplicationPackageCollectionItem", "privateApplicationId");
            }
            this.privateApplicationId = privateApplicationId;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetPrivateApplicationPackagesPrivateApplicationPackageCollectionItem", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder version(String version) {
            if (version == null) {
              throw new MissingRequiredPropertyException("GetPrivateApplicationPackagesPrivateApplicationPackageCollectionItem", "version");
            }
            this.version = version;
            return this;
        }
        public GetPrivateApplicationPackagesPrivateApplicationPackageCollectionItem build() {
            final var _resultValue = new GetPrivateApplicationPackagesPrivateApplicationPackageCollectionItem();
            _resultValue.contentUrl = contentUrl;
            _resultValue.displayName = displayName;
            _resultValue.id = id;
            _resultValue.mimeType = mimeType;
            _resultValue.packageType = packageType;
            _resultValue.privateApplicationId = privateApplicationId;
            _resultValue.timeCreated = timeCreated;
            _resultValue.version = version;
            return _resultValue;
        }
    }
}
