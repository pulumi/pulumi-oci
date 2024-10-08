// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsManagementHub.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.OsManagementHub.outputs.GetManagedInstanceAvailablePackagesAvailablePackageCollectionItemSoftwareSource;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetManagedInstanceAvailablePackagesAvailablePackageCollectionItem {
    /**
     * @return The architecture for which this package was built.
     * 
     */
    private String architecture;
    /**
     * @return A filter to return resources that match the given display names.
     * 
     */
    private String displayName;
    /**
     * @return Unique identifier for the package.
     * 
     */
    private String name;
    /**
     * @return Status of the software package.
     * 
     */
    private String packageClassification;
    /**
     * @return List of software sources that provide the software package.
     * 
     */
    private List<GetManagedInstanceAvailablePackagesAvailablePackageCollectionItemSoftwareSource> softwareSources;
    /**
     * @return Type of the package.
     * 
     */
    private String type;
    /**
     * @return Version of the installed package.
     * 
     */
    private String version;

    private GetManagedInstanceAvailablePackagesAvailablePackageCollectionItem() {}
    /**
     * @return The architecture for which this package was built.
     * 
     */
    public String architecture() {
        return this.architecture;
    }
    /**
     * @return A filter to return resources that match the given display names.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return Unique identifier for the package.
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return Status of the software package.
     * 
     */
    public String packageClassification() {
        return this.packageClassification;
    }
    /**
     * @return List of software sources that provide the software package.
     * 
     */
    public List<GetManagedInstanceAvailablePackagesAvailablePackageCollectionItemSoftwareSource> softwareSources() {
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
     * @return Version of the installed package.
     * 
     */
    public String version() {
        return this.version;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetManagedInstanceAvailablePackagesAvailablePackageCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String architecture;
        private String displayName;
        private String name;
        private String packageClassification;
        private List<GetManagedInstanceAvailablePackagesAvailablePackageCollectionItemSoftwareSource> softwareSources;
        private String type;
        private String version;
        public Builder() {}
        public Builder(GetManagedInstanceAvailablePackagesAvailablePackageCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.architecture = defaults.architecture;
    	      this.displayName = defaults.displayName;
    	      this.name = defaults.name;
    	      this.packageClassification = defaults.packageClassification;
    	      this.softwareSources = defaults.softwareSources;
    	      this.type = defaults.type;
    	      this.version = defaults.version;
        }

        @CustomType.Setter
        public Builder architecture(String architecture) {
            if (architecture == null) {
              throw new MissingRequiredPropertyException("GetManagedInstanceAvailablePackagesAvailablePackageCollectionItem", "architecture");
            }
            this.architecture = architecture;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetManagedInstanceAvailablePackagesAvailablePackageCollectionItem", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("GetManagedInstanceAvailablePackagesAvailablePackageCollectionItem", "name");
            }
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder packageClassification(String packageClassification) {
            if (packageClassification == null) {
              throw new MissingRequiredPropertyException("GetManagedInstanceAvailablePackagesAvailablePackageCollectionItem", "packageClassification");
            }
            this.packageClassification = packageClassification;
            return this;
        }
        @CustomType.Setter
        public Builder softwareSources(List<GetManagedInstanceAvailablePackagesAvailablePackageCollectionItemSoftwareSource> softwareSources) {
            if (softwareSources == null) {
              throw new MissingRequiredPropertyException("GetManagedInstanceAvailablePackagesAvailablePackageCollectionItem", "softwareSources");
            }
            this.softwareSources = softwareSources;
            return this;
        }
        public Builder softwareSources(GetManagedInstanceAvailablePackagesAvailablePackageCollectionItemSoftwareSource... softwareSources) {
            return softwareSources(List.of(softwareSources));
        }
        @CustomType.Setter
        public Builder type(String type) {
            if (type == null) {
              throw new MissingRequiredPropertyException("GetManagedInstanceAvailablePackagesAvailablePackageCollectionItem", "type");
            }
            this.type = type;
            return this;
        }
        @CustomType.Setter
        public Builder version(String version) {
            if (version == null) {
              throw new MissingRequiredPropertyException("GetManagedInstanceAvailablePackagesAvailablePackageCollectionItem", "version");
            }
            this.version = version;
            return this;
        }
        public GetManagedInstanceAvailablePackagesAvailablePackageCollectionItem build() {
            final var _resultValue = new GetManagedInstanceAvailablePackagesAvailablePackageCollectionItem();
            _resultValue.architecture = architecture;
            _resultValue.displayName = displayName;
            _resultValue.name = name;
            _resultValue.packageClassification = packageClassification;
            _resultValue.softwareSources = softwareSources;
            _resultValue.type = type;
            _resultValue.version = version;
            return _resultValue;
        }
    }
}
