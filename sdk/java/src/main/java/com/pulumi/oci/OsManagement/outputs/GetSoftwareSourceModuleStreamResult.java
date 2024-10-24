// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetSoftwareSourceModuleStreamResult {
    /**
     * @return The architecture for which the packages in this module stream were built
     * 
     */
    private String architecture;
    /**
     * @return A description of the contents of the module stream
     * 
     */
    private String description;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return Indicates if this stream is the default for its module.
     * 
     */
    private Boolean isDefault;
    /**
     * @return The name of the module that contains the stream
     * 
     */
    private String moduleName;
    /**
     * @return A list of packages that are contained by the stream.  Each element in the list is the name of a package.  The name is suitable to use as an argument to other OS Management APIs that interact directly with packages.
     * 
     */
    private List<String> packages;
    /**
     * @return A list of profiles that are part of the stream.  Each element in the list is the name of a profile.  The name is suitable to use as an argument to other OS Management APIs that interact directly with module stream profiles.  However, it is not URL encoded.
     * 
     */
    private List<String> profiles;
    /**
     * @return The OCID of the software source that provides this module stream.
     * 
     */
    private String softwareSourceId;
    /**
     * @return The name of the stream
     * 
     */
    private String streamName;

    private GetSoftwareSourceModuleStreamResult() {}
    /**
     * @return The architecture for which the packages in this module stream were built
     * 
     */
    public String architecture() {
        return this.architecture;
    }
    /**
     * @return A description of the contents of the module stream
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Indicates if this stream is the default for its module.
     * 
     */
    public Boolean isDefault() {
        return this.isDefault;
    }
    /**
     * @return The name of the module that contains the stream
     * 
     */
    public String moduleName() {
        return this.moduleName;
    }
    /**
     * @return A list of packages that are contained by the stream.  Each element in the list is the name of a package.  The name is suitable to use as an argument to other OS Management APIs that interact directly with packages.
     * 
     */
    public List<String> packages() {
        return this.packages;
    }
    /**
     * @return A list of profiles that are part of the stream.  Each element in the list is the name of a profile.  The name is suitable to use as an argument to other OS Management APIs that interact directly with module stream profiles.  However, it is not URL encoded.
     * 
     */
    public List<String> profiles() {
        return this.profiles;
    }
    /**
     * @return The OCID of the software source that provides this module stream.
     * 
     */
    public String softwareSourceId() {
        return this.softwareSourceId;
    }
    /**
     * @return The name of the stream
     * 
     */
    public String streamName() {
        return this.streamName;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetSoftwareSourceModuleStreamResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String architecture;
        private String description;
        private String id;
        private Boolean isDefault;
        private String moduleName;
        private List<String> packages;
        private List<String> profiles;
        private String softwareSourceId;
        private String streamName;
        public Builder() {}
        public Builder(GetSoftwareSourceModuleStreamResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.architecture = defaults.architecture;
    	      this.description = defaults.description;
    	      this.id = defaults.id;
    	      this.isDefault = defaults.isDefault;
    	      this.moduleName = defaults.moduleName;
    	      this.packages = defaults.packages;
    	      this.profiles = defaults.profiles;
    	      this.softwareSourceId = defaults.softwareSourceId;
    	      this.streamName = defaults.streamName;
        }

        @CustomType.Setter
        public Builder architecture(String architecture) {
            if (architecture == null) {
              throw new MissingRequiredPropertyException("GetSoftwareSourceModuleStreamResult", "architecture");
            }
            this.architecture = architecture;
            return this;
        }
        @CustomType.Setter
        public Builder description(String description) {
            if (description == null) {
              throw new MissingRequiredPropertyException("GetSoftwareSourceModuleStreamResult", "description");
            }
            this.description = description;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetSoftwareSourceModuleStreamResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder isDefault(Boolean isDefault) {
            if (isDefault == null) {
              throw new MissingRequiredPropertyException("GetSoftwareSourceModuleStreamResult", "isDefault");
            }
            this.isDefault = isDefault;
            return this;
        }
        @CustomType.Setter
        public Builder moduleName(String moduleName) {
            if (moduleName == null) {
              throw new MissingRequiredPropertyException("GetSoftwareSourceModuleStreamResult", "moduleName");
            }
            this.moduleName = moduleName;
            return this;
        }
        @CustomType.Setter
        public Builder packages(List<String> packages) {
            if (packages == null) {
              throw new MissingRequiredPropertyException("GetSoftwareSourceModuleStreamResult", "packages");
            }
            this.packages = packages;
            return this;
        }
        public Builder packages(String... packages) {
            return packages(List.of(packages));
        }
        @CustomType.Setter
        public Builder profiles(List<String> profiles) {
            if (profiles == null) {
              throw new MissingRequiredPropertyException("GetSoftwareSourceModuleStreamResult", "profiles");
            }
            this.profiles = profiles;
            return this;
        }
        public Builder profiles(String... profiles) {
            return profiles(List.of(profiles));
        }
        @CustomType.Setter
        public Builder softwareSourceId(String softwareSourceId) {
            if (softwareSourceId == null) {
              throw new MissingRequiredPropertyException("GetSoftwareSourceModuleStreamResult", "softwareSourceId");
            }
            this.softwareSourceId = softwareSourceId;
            return this;
        }
        @CustomType.Setter
        public Builder streamName(String streamName) {
            if (streamName == null) {
              throw new MissingRequiredPropertyException("GetSoftwareSourceModuleStreamResult", "streamName");
            }
            this.streamName = streamName;
            return this;
        }
        public GetSoftwareSourceModuleStreamResult build() {
            final var _resultValue = new GetSoftwareSourceModuleStreamResult();
            _resultValue.architecture = architecture;
            _resultValue.description = description;
            _resultValue.id = id;
            _resultValue.isDefault = isDefault;
            _resultValue.moduleName = moduleName;
            _resultValue.packages = packages;
            _resultValue.profiles = profiles;
            _resultValue.softwareSourceId = softwareSourceId;
            _resultValue.streamName = streamName;
            return _resultValue;
        }
    }
}
