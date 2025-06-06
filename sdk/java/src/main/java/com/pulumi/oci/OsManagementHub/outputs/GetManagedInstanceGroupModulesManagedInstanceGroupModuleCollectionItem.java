// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsManagementHub.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetManagedInstanceGroupModulesManagedInstanceGroupModuleCollectionItem {
    /**
     * @return The name of the module stream that is enabled for the group.
     * 
     */
    private String enabledStream;
    /**
     * @return The list of installed profiles under the currently enabled module stream.
     * 
     */
    private List<String> installedProfiles;
    /**
     * @return The resource name.
     * 
     */
    private String name;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the software source that provides this module stream.
     * 
     */
    private String softwareSourceId;

    private GetManagedInstanceGroupModulesManagedInstanceGroupModuleCollectionItem() {}
    /**
     * @return The name of the module stream that is enabled for the group.
     * 
     */
    public String enabledStream() {
        return this.enabledStream;
    }
    /**
     * @return The list of installed profiles under the currently enabled module stream.
     * 
     */
    public List<String> installedProfiles() {
        return this.installedProfiles;
    }
    /**
     * @return The resource name.
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the software source that provides this module stream.
     * 
     */
    public String softwareSourceId() {
        return this.softwareSourceId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetManagedInstanceGroupModulesManagedInstanceGroupModuleCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String enabledStream;
        private List<String> installedProfiles;
        private String name;
        private String softwareSourceId;
        public Builder() {}
        public Builder(GetManagedInstanceGroupModulesManagedInstanceGroupModuleCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.enabledStream = defaults.enabledStream;
    	      this.installedProfiles = defaults.installedProfiles;
    	      this.name = defaults.name;
    	      this.softwareSourceId = defaults.softwareSourceId;
        }

        @CustomType.Setter
        public Builder enabledStream(String enabledStream) {
            if (enabledStream == null) {
              throw new MissingRequiredPropertyException("GetManagedInstanceGroupModulesManagedInstanceGroupModuleCollectionItem", "enabledStream");
            }
            this.enabledStream = enabledStream;
            return this;
        }
        @CustomType.Setter
        public Builder installedProfiles(List<String> installedProfiles) {
            if (installedProfiles == null) {
              throw new MissingRequiredPropertyException("GetManagedInstanceGroupModulesManagedInstanceGroupModuleCollectionItem", "installedProfiles");
            }
            this.installedProfiles = installedProfiles;
            return this;
        }
        public Builder installedProfiles(String... installedProfiles) {
            return installedProfiles(List.of(installedProfiles));
        }
        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("GetManagedInstanceGroupModulesManagedInstanceGroupModuleCollectionItem", "name");
            }
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder softwareSourceId(String softwareSourceId) {
            if (softwareSourceId == null) {
              throw new MissingRequiredPropertyException("GetManagedInstanceGroupModulesManagedInstanceGroupModuleCollectionItem", "softwareSourceId");
            }
            this.softwareSourceId = softwareSourceId;
            return this;
        }
        public GetManagedInstanceGroupModulesManagedInstanceGroupModuleCollectionItem build() {
            final var _resultValue = new GetManagedInstanceGroupModulesManagedInstanceGroupModuleCollectionItem();
            _resultValue.enabledStream = enabledStream;
            _resultValue.installedProfiles = installedProfiles;
            _resultValue.name = name;
            _resultValue.softwareSourceId = softwareSourceId;
            return _resultValue;
        }
    }
}
