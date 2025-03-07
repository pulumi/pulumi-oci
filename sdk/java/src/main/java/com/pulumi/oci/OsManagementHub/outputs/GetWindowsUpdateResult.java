// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsManagementHub.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetWindowsUpdateResult {
    /**
     * @return Description of the update.
     * 
     */
    private String description;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return Indicates whether the update can be installed using the service.
     * 
     */
    private String installable;
    /**
     * @return List of requirements for installing the update on the managed instance.
     * 
     */
    private List<String> installationRequirements;
    /**
     * @return Indicates whether a reboot is required to complete the installation of this update.
     * 
     */
    private Boolean isRebootRequiredForInstallation;
    /**
     * @return List of the Microsoft Knowledge Base Article Ids related to this Windows Update.
     * 
     */
    private List<String> kbArticleIds;
    /**
     * @return Name of the Windows update.
     * 
     */
    private String name;
    /**
     * @return size of the package in bytes
     * 
     */
    private String sizeInBytes;
    /**
     * @return Unique identifier for the Windows update. Note that this is not an OCID, but is a unique identifier assigned by Microsoft.  Example: &#39;6981d463-cd91-4a26-b7c4-ea4ded9183ed&#39;
     * 
     */
    private String updateId;
    /**
     * @return The type of Windows update.
     * 
     */
    private String updateType;
    private String windowsUpdateId;

    private GetWindowsUpdateResult() {}
    /**
     * @return Description of the update.
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
     * @return Indicates whether the update can be installed using the service.
     * 
     */
    public String installable() {
        return this.installable;
    }
    /**
     * @return List of requirements for installing the update on the managed instance.
     * 
     */
    public List<String> installationRequirements() {
        return this.installationRequirements;
    }
    /**
     * @return Indicates whether a reboot is required to complete the installation of this update.
     * 
     */
    public Boolean isRebootRequiredForInstallation() {
        return this.isRebootRequiredForInstallation;
    }
    /**
     * @return List of the Microsoft Knowledge Base Article Ids related to this Windows Update.
     * 
     */
    public List<String> kbArticleIds() {
        return this.kbArticleIds;
    }
    /**
     * @return Name of the Windows update.
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return size of the package in bytes
     * 
     */
    public String sizeInBytes() {
        return this.sizeInBytes;
    }
    /**
     * @return Unique identifier for the Windows update. Note that this is not an OCID, but is a unique identifier assigned by Microsoft.  Example: &#39;6981d463-cd91-4a26-b7c4-ea4ded9183ed&#39;
     * 
     */
    public String updateId() {
        return this.updateId;
    }
    /**
     * @return The type of Windows update.
     * 
     */
    public String updateType() {
        return this.updateType;
    }
    public String windowsUpdateId() {
        return this.windowsUpdateId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetWindowsUpdateResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String description;
        private String id;
        private String installable;
        private List<String> installationRequirements;
        private Boolean isRebootRequiredForInstallation;
        private List<String> kbArticleIds;
        private String name;
        private String sizeInBytes;
        private String updateId;
        private String updateType;
        private String windowsUpdateId;
        public Builder() {}
        public Builder(GetWindowsUpdateResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.description = defaults.description;
    	      this.id = defaults.id;
    	      this.installable = defaults.installable;
    	      this.installationRequirements = defaults.installationRequirements;
    	      this.isRebootRequiredForInstallation = defaults.isRebootRequiredForInstallation;
    	      this.kbArticleIds = defaults.kbArticleIds;
    	      this.name = defaults.name;
    	      this.sizeInBytes = defaults.sizeInBytes;
    	      this.updateId = defaults.updateId;
    	      this.updateType = defaults.updateType;
    	      this.windowsUpdateId = defaults.windowsUpdateId;
        }

        @CustomType.Setter
        public Builder description(String description) {
            if (description == null) {
              throw new MissingRequiredPropertyException("GetWindowsUpdateResult", "description");
            }
            this.description = description;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetWindowsUpdateResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder installable(String installable) {
            if (installable == null) {
              throw new MissingRequiredPropertyException("GetWindowsUpdateResult", "installable");
            }
            this.installable = installable;
            return this;
        }
        @CustomType.Setter
        public Builder installationRequirements(List<String> installationRequirements) {
            if (installationRequirements == null) {
              throw new MissingRequiredPropertyException("GetWindowsUpdateResult", "installationRequirements");
            }
            this.installationRequirements = installationRequirements;
            return this;
        }
        public Builder installationRequirements(String... installationRequirements) {
            return installationRequirements(List.of(installationRequirements));
        }
        @CustomType.Setter
        public Builder isRebootRequiredForInstallation(Boolean isRebootRequiredForInstallation) {
            if (isRebootRequiredForInstallation == null) {
              throw new MissingRequiredPropertyException("GetWindowsUpdateResult", "isRebootRequiredForInstallation");
            }
            this.isRebootRequiredForInstallation = isRebootRequiredForInstallation;
            return this;
        }
        @CustomType.Setter
        public Builder kbArticleIds(List<String> kbArticleIds) {
            if (kbArticleIds == null) {
              throw new MissingRequiredPropertyException("GetWindowsUpdateResult", "kbArticleIds");
            }
            this.kbArticleIds = kbArticleIds;
            return this;
        }
        public Builder kbArticleIds(String... kbArticleIds) {
            return kbArticleIds(List.of(kbArticleIds));
        }
        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("GetWindowsUpdateResult", "name");
            }
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder sizeInBytes(String sizeInBytes) {
            if (sizeInBytes == null) {
              throw new MissingRequiredPropertyException("GetWindowsUpdateResult", "sizeInBytes");
            }
            this.sizeInBytes = sizeInBytes;
            return this;
        }
        @CustomType.Setter
        public Builder updateId(String updateId) {
            if (updateId == null) {
              throw new MissingRequiredPropertyException("GetWindowsUpdateResult", "updateId");
            }
            this.updateId = updateId;
            return this;
        }
        @CustomType.Setter
        public Builder updateType(String updateType) {
            if (updateType == null) {
              throw new MissingRequiredPropertyException("GetWindowsUpdateResult", "updateType");
            }
            this.updateType = updateType;
            return this;
        }
        @CustomType.Setter
        public Builder windowsUpdateId(String windowsUpdateId) {
            if (windowsUpdateId == null) {
              throw new MissingRequiredPropertyException("GetWindowsUpdateResult", "windowsUpdateId");
            }
            this.windowsUpdateId = windowsUpdateId;
            return this;
        }
        public GetWindowsUpdateResult build() {
            final var _resultValue = new GetWindowsUpdateResult();
            _resultValue.description = description;
            _resultValue.id = id;
            _resultValue.installable = installable;
            _resultValue.installationRequirements = installationRequirements;
            _resultValue.isRebootRequiredForInstallation = isRebootRequiredForInstallation;
            _resultValue.kbArticleIds = kbArticleIds;
            _resultValue.name = name;
            _resultValue.sizeInBytes = sizeInBytes;
            _resultValue.updateId = updateId;
            _resultValue.updateType = updateType;
            _resultValue.windowsUpdateId = windowsUpdateId;
            return _resultValue;
        }
    }
}
