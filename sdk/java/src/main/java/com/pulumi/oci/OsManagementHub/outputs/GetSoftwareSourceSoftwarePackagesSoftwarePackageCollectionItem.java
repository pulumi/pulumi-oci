// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsManagementHub.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.OsManagementHub.outputs.GetSoftwareSourceSoftwarePackagesSoftwarePackageCollectionItemDependency;
import com.pulumi.oci.OsManagementHub.outputs.GetSoftwareSourceSoftwarePackagesSoftwarePackageCollectionItemFile;
import com.pulumi.oci.OsManagementHub.outputs.GetSoftwareSourceSoftwarePackagesSoftwarePackageCollectionItemSoftwareSource;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetSoftwareSourceSoftwarePackagesSoftwarePackageCollectionItem {
    /**
     * @return The architecture for which this software was built
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
    private List<GetSoftwareSourceSoftwarePackagesSoftwarePackageCollectionItemDependency> dependencies;
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
    private List<GetSoftwareSourceSoftwarePackagesSoftwarePackageCollectionItemFile> files;
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
    private List<GetSoftwareSourceSoftwarePackagesSoftwarePackageCollectionItemSoftwareSource> softwareSources;
    /**
     * @return Type of the package.
     * 
     */
    private String type;
    /**
     * @return Version of the package.
     * 
     */
    private String version;

    private GetSoftwareSourceSoftwarePackagesSoftwarePackageCollectionItem() {}
    /**
     * @return The architecture for which this software was built
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
    public List<GetSoftwareSourceSoftwarePackagesSoftwarePackageCollectionItemDependency> dependencies() {
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
    public List<GetSoftwareSourceSoftwarePackagesSoftwarePackageCollectionItemFile> files() {
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
    public List<GetSoftwareSourceSoftwarePackagesSoftwarePackageCollectionItemSoftwareSource> softwareSources() {
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
     * @return Version of the package.
     * 
     */
    public String version() {
        return this.version;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetSoftwareSourceSoftwarePackagesSoftwarePackageCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String architecture;
        private String checksum;
        private String checksumType;
        private List<GetSoftwareSourceSoftwarePackagesSoftwarePackageCollectionItemDependency> dependencies;
        private String description;
        private String displayName;
        private List<GetSoftwareSourceSoftwarePackagesSoftwarePackageCollectionItemFile> files;
        private Boolean isLatest;
        private String lastModifiedDate;
        private String name;
        private List<String> osFamilies;
        private String sizeInBytes;
        private List<GetSoftwareSourceSoftwarePackagesSoftwarePackageCollectionItemSoftwareSource> softwareSources;
        private String type;
        private String version;
        public Builder() {}
        public Builder(GetSoftwareSourceSoftwarePackagesSoftwarePackageCollectionItem defaults) {
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
              throw new MissingRequiredPropertyException("GetSoftwareSourceSoftwarePackagesSoftwarePackageCollectionItem", "architecture");
            }
            this.architecture = architecture;
            return this;
        }
        @CustomType.Setter
        public Builder checksum(String checksum) {
            if (checksum == null) {
              throw new MissingRequiredPropertyException("GetSoftwareSourceSoftwarePackagesSoftwarePackageCollectionItem", "checksum");
            }
            this.checksum = checksum;
            return this;
        }
        @CustomType.Setter
        public Builder checksumType(String checksumType) {
            if (checksumType == null) {
              throw new MissingRequiredPropertyException("GetSoftwareSourceSoftwarePackagesSoftwarePackageCollectionItem", "checksumType");
            }
            this.checksumType = checksumType;
            return this;
        }
        @CustomType.Setter
        public Builder dependencies(List<GetSoftwareSourceSoftwarePackagesSoftwarePackageCollectionItemDependency> dependencies) {
            if (dependencies == null) {
              throw new MissingRequiredPropertyException("GetSoftwareSourceSoftwarePackagesSoftwarePackageCollectionItem", "dependencies");
            }
            this.dependencies = dependencies;
            return this;
        }
        public Builder dependencies(GetSoftwareSourceSoftwarePackagesSoftwarePackageCollectionItemDependency... dependencies) {
            return dependencies(List.of(dependencies));
        }
        @CustomType.Setter
        public Builder description(String description) {
            if (description == null) {
              throw new MissingRequiredPropertyException("GetSoftwareSourceSoftwarePackagesSoftwarePackageCollectionItem", "description");
            }
            this.description = description;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetSoftwareSourceSoftwarePackagesSoftwarePackageCollectionItem", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder files(List<GetSoftwareSourceSoftwarePackagesSoftwarePackageCollectionItemFile> files) {
            if (files == null) {
              throw new MissingRequiredPropertyException("GetSoftwareSourceSoftwarePackagesSoftwarePackageCollectionItem", "files");
            }
            this.files = files;
            return this;
        }
        public Builder files(GetSoftwareSourceSoftwarePackagesSoftwarePackageCollectionItemFile... files) {
            return files(List.of(files));
        }
        @CustomType.Setter
        public Builder isLatest(Boolean isLatest) {
            if (isLatest == null) {
              throw new MissingRequiredPropertyException("GetSoftwareSourceSoftwarePackagesSoftwarePackageCollectionItem", "isLatest");
            }
            this.isLatest = isLatest;
            return this;
        }
        @CustomType.Setter
        public Builder lastModifiedDate(String lastModifiedDate) {
            if (lastModifiedDate == null) {
              throw new MissingRequiredPropertyException("GetSoftwareSourceSoftwarePackagesSoftwarePackageCollectionItem", "lastModifiedDate");
            }
            this.lastModifiedDate = lastModifiedDate;
            return this;
        }
        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("GetSoftwareSourceSoftwarePackagesSoftwarePackageCollectionItem", "name");
            }
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder osFamilies(List<String> osFamilies) {
            if (osFamilies == null) {
              throw new MissingRequiredPropertyException("GetSoftwareSourceSoftwarePackagesSoftwarePackageCollectionItem", "osFamilies");
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
              throw new MissingRequiredPropertyException("GetSoftwareSourceSoftwarePackagesSoftwarePackageCollectionItem", "sizeInBytes");
            }
            this.sizeInBytes = sizeInBytes;
            return this;
        }
        @CustomType.Setter
        public Builder softwareSources(List<GetSoftwareSourceSoftwarePackagesSoftwarePackageCollectionItemSoftwareSource> softwareSources) {
            if (softwareSources == null) {
              throw new MissingRequiredPropertyException("GetSoftwareSourceSoftwarePackagesSoftwarePackageCollectionItem", "softwareSources");
            }
            this.softwareSources = softwareSources;
            return this;
        }
        public Builder softwareSources(GetSoftwareSourceSoftwarePackagesSoftwarePackageCollectionItemSoftwareSource... softwareSources) {
            return softwareSources(List.of(softwareSources));
        }
        @CustomType.Setter
        public Builder type(String type) {
            if (type == null) {
              throw new MissingRequiredPropertyException("GetSoftwareSourceSoftwarePackagesSoftwarePackageCollectionItem", "type");
            }
            this.type = type;
            return this;
        }
        @CustomType.Setter
        public Builder version(String version) {
            if (version == null) {
              throw new MissingRequiredPropertyException("GetSoftwareSourceSoftwarePackagesSoftwarePackageCollectionItem", "version");
            }
            this.version = version;
            return this;
        }
        public GetSoftwareSourceSoftwarePackagesSoftwarePackageCollectionItem build() {
            final var _resultValue = new GetSoftwareSourceSoftwarePackagesSoftwarePackageCollectionItem();
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
