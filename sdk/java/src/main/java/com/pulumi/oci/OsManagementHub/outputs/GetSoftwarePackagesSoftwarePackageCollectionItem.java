// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsManagementHub.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.OsManagementHub.outputs.GetSoftwarePackagesSoftwarePackageCollectionItemDependency;
import com.pulumi.oci.OsManagementHub.outputs.GetSoftwarePackagesSoftwarePackageCollectionItemFile;
import com.pulumi.oci.OsManagementHub.outputs.GetSoftwarePackagesSoftwarePackageCollectionItemSoftwareSource;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetSoftwarePackagesSoftwarePackageCollectionItem {
    /**
     * @return A filter to return software packages that match the given architecture.
     * 
     */
    private String architecture;
    /**
     * @return Checksum of the file.
     * 
     */
    private String checksum;
    /**
     * @return Type of the checksum.
     * 
     */
    private String checksumType;
    /**
     * @return List of dependencies for the software package.
     * 
     */
    private List<GetSoftwarePackagesSoftwarePackageCollectionItemDependency> dependencies;
    /**
     * @return Software source description.
     * 
     */
    private String description;
    /**
     * @return A filter to return resources that match the given user-friendly name.
     * 
     */
    private String displayName;
    /**
     * @return List of files for the software package.
     * 
     */
    private List<GetSoftwarePackagesSoftwarePackageCollectionItemFile> files;
    /**
     * @return Indicates whether to list only the latest versions of packages, module streams, and stream profiles.
     * 
     */
    private Boolean isLatest;
    /**
     * @return The date and time the package was last modified (in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) format).
     * 
     */
    private String lastModifiedDate;
    /**
     * @return Unique identifier for the package. Note that this is not an OCID.
     * 
     */
    private String name;
    /**
     * @return The OS families the package belongs to.
     * 
     */
    private List<String> osFamilies;
    /**
     * @return Size of the package in bytes.
     * 
     */
    private String sizeInBytes;
    /**
     * @return List of software sources that provide the software package. This property is deprecated and it will be removed in a future API release.
     * 
     */
    private List<GetSoftwarePackagesSoftwarePackageCollectionItemSoftwareSource> softwareSources;
    /**
     * @return Type of the package.
     * 
     */
    private String type;
    /**
     * @return A filter to return software packages that match the given version.
     * 
     */
    private String version;

    private GetSoftwarePackagesSoftwarePackageCollectionItem() {}
    /**
     * @return A filter to return software packages that match the given architecture.
     * 
     */
    public String architecture() {
        return this.architecture;
    }
    /**
     * @return Checksum of the file.
     * 
     */
    public String checksum() {
        return this.checksum;
    }
    /**
     * @return Type of the checksum.
     * 
     */
    public String checksumType() {
        return this.checksumType;
    }
    /**
     * @return List of dependencies for the software package.
     * 
     */
    public List<GetSoftwarePackagesSoftwarePackageCollectionItemDependency> dependencies() {
        return this.dependencies;
    }
    /**
     * @return Software source description.
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return A filter to return resources that match the given user-friendly name.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return List of files for the software package.
     * 
     */
    public List<GetSoftwarePackagesSoftwarePackageCollectionItemFile> files() {
        return this.files;
    }
    /**
     * @return Indicates whether to list only the latest versions of packages, module streams, and stream profiles.
     * 
     */
    public Boolean isLatest() {
        return this.isLatest;
    }
    /**
     * @return The date and time the package was last modified (in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) format).
     * 
     */
    public String lastModifiedDate() {
        return this.lastModifiedDate;
    }
    /**
     * @return Unique identifier for the package. Note that this is not an OCID.
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return The OS families the package belongs to.
     * 
     */
    public List<String> osFamilies() {
        return this.osFamilies;
    }
    /**
     * @return Size of the package in bytes.
     * 
     */
    public String sizeInBytes() {
        return this.sizeInBytes;
    }
    /**
     * @return List of software sources that provide the software package. This property is deprecated and it will be removed in a future API release.
     * 
     */
    public List<GetSoftwarePackagesSoftwarePackageCollectionItemSoftwareSource> softwareSources() {
        return this.softwareSources;
    }
    /**
     * @return Type of the package.
     * 
     */
    public String type() {
        return this.type;
    }
    /**
     * @return A filter to return software packages that match the given version.
     * 
     */
    public String version() {
        return this.version;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetSoftwarePackagesSoftwarePackageCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String architecture;
        private String checksum;
        private String checksumType;
        private List<GetSoftwarePackagesSoftwarePackageCollectionItemDependency> dependencies;
        private String description;
        private String displayName;
        private List<GetSoftwarePackagesSoftwarePackageCollectionItemFile> files;
        private Boolean isLatest;
        private String lastModifiedDate;
        private String name;
        private List<String> osFamilies;
        private String sizeInBytes;
        private List<GetSoftwarePackagesSoftwarePackageCollectionItemSoftwareSource> softwareSources;
        private String type;
        private String version;
        public Builder() {}
        public Builder(GetSoftwarePackagesSoftwarePackageCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.architecture = defaults.architecture;
    	      this.checksum = defaults.checksum;
    	      this.checksumType = defaults.checksumType;
    	      this.dependencies = defaults.dependencies;
    	      this.description = defaults.description;
    	      this.displayName = defaults.displayName;
    	      this.files = defaults.files;
    	      this.isLatest = defaults.isLatest;
    	      this.lastModifiedDate = defaults.lastModifiedDate;
    	      this.name = defaults.name;
    	      this.osFamilies = defaults.osFamilies;
    	      this.sizeInBytes = defaults.sizeInBytes;
    	      this.softwareSources = defaults.softwareSources;
    	      this.type = defaults.type;
    	      this.version = defaults.version;
        }

        @CustomType.Setter
        public Builder architecture(String architecture) {
            if (architecture == null) {
              throw new MissingRequiredPropertyException("GetSoftwarePackagesSoftwarePackageCollectionItem", "architecture");
            }
            this.architecture = architecture;
            return this;
        }
        @CustomType.Setter
        public Builder checksum(String checksum) {
            if (checksum == null) {
              throw new MissingRequiredPropertyException("GetSoftwarePackagesSoftwarePackageCollectionItem", "checksum");
            }
            this.checksum = checksum;
            return this;
        }
        @CustomType.Setter
        public Builder checksumType(String checksumType) {
            if (checksumType == null) {
              throw new MissingRequiredPropertyException("GetSoftwarePackagesSoftwarePackageCollectionItem", "checksumType");
            }
            this.checksumType = checksumType;
            return this;
        }
        @CustomType.Setter
        public Builder dependencies(List<GetSoftwarePackagesSoftwarePackageCollectionItemDependency> dependencies) {
            if (dependencies == null) {
              throw new MissingRequiredPropertyException("GetSoftwarePackagesSoftwarePackageCollectionItem", "dependencies");
            }
            this.dependencies = dependencies;
            return this;
        }
        public Builder dependencies(GetSoftwarePackagesSoftwarePackageCollectionItemDependency... dependencies) {
            return dependencies(List.of(dependencies));
        }
        @CustomType.Setter
        public Builder description(String description) {
            if (description == null) {
              throw new MissingRequiredPropertyException("GetSoftwarePackagesSoftwarePackageCollectionItem", "description");
            }
            this.description = description;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetSoftwarePackagesSoftwarePackageCollectionItem", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder files(List<GetSoftwarePackagesSoftwarePackageCollectionItemFile> files) {
            if (files == null) {
              throw new MissingRequiredPropertyException("GetSoftwarePackagesSoftwarePackageCollectionItem", "files");
            }
            this.files = files;
            return this;
        }
        public Builder files(GetSoftwarePackagesSoftwarePackageCollectionItemFile... files) {
            return files(List.of(files));
        }
        @CustomType.Setter
        public Builder isLatest(Boolean isLatest) {
            if (isLatest == null) {
              throw new MissingRequiredPropertyException("GetSoftwarePackagesSoftwarePackageCollectionItem", "isLatest");
            }
            this.isLatest = isLatest;
            return this;
        }
        @CustomType.Setter
        public Builder lastModifiedDate(String lastModifiedDate) {
            if (lastModifiedDate == null) {
              throw new MissingRequiredPropertyException("GetSoftwarePackagesSoftwarePackageCollectionItem", "lastModifiedDate");
            }
            this.lastModifiedDate = lastModifiedDate;
            return this;
        }
        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("GetSoftwarePackagesSoftwarePackageCollectionItem", "name");
            }
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder osFamilies(List<String> osFamilies) {
            if (osFamilies == null) {
              throw new MissingRequiredPropertyException("GetSoftwarePackagesSoftwarePackageCollectionItem", "osFamilies");
            }
            this.osFamilies = osFamilies;
            return this;
        }
        public Builder osFamilies(String... osFamilies) {
            return osFamilies(List.of(osFamilies));
        }
        @CustomType.Setter
        public Builder sizeInBytes(String sizeInBytes) {
            if (sizeInBytes == null) {
              throw new MissingRequiredPropertyException("GetSoftwarePackagesSoftwarePackageCollectionItem", "sizeInBytes");
            }
            this.sizeInBytes = sizeInBytes;
            return this;
        }
        @CustomType.Setter
        public Builder softwareSources(List<GetSoftwarePackagesSoftwarePackageCollectionItemSoftwareSource> softwareSources) {
            if (softwareSources == null) {
              throw new MissingRequiredPropertyException("GetSoftwarePackagesSoftwarePackageCollectionItem", "softwareSources");
            }
            this.softwareSources = softwareSources;
            return this;
        }
        public Builder softwareSources(GetSoftwarePackagesSoftwarePackageCollectionItemSoftwareSource... softwareSources) {
            return softwareSources(List.of(softwareSources));
        }
        @CustomType.Setter
        public Builder type(String type) {
            if (type == null) {
              throw new MissingRequiredPropertyException("GetSoftwarePackagesSoftwarePackageCollectionItem", "type");
            }
            this.type = type;
            return this;
        }
        @CustomType.Setter
        public Builder version(String version) {
            if (version == null) {
              throw new MissingRequiredPropertyException("GetSoftwarePackagesSoftwarePackageCollectionItem", "version");
            }
            this.version = version;
            return this;
        }
        public GetSoftwarePackagesSoftwarePackageCollectionItem build() {
            final var _resultValue = new GetSoftwarePackagesSoftwarePackageCollectionItem();
            _resultValue.architecture = architecture;
            _resultValue.checksum = checksum;
            _resultValue.checksumType = checksumType;
            _resultValue.dependencies = dependencies;
            _resultValue.description = description;
            _resultValue.displayName = displayName;
            _resultValue.files = files;
            _resultValue.isLatest = isLatest;
            _resultValue.lastModifiedDate = lastModifiedDate;
            _resultValue.name = name;
            _resultValue.osFamilies = osFamilies;
            _resultValue.sizeInBytes = sizeInBytes;
            _resultValue.softwareSources = softwareSources;
            _resultValue.type = type;
            _resultValue.version = version;
            return _resultValue;
        }
    }
}
