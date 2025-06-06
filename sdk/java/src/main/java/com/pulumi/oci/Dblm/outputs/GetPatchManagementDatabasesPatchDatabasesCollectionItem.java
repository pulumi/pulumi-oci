// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Dblm.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Dblm.outputs.GetPatchManagementDatabasesPatchDatabasesCollectionItemAdditionalPatch;
import com.pulumi.oci.Dblm.outputs.GetPatchManagementDatabasesPatchDatabasesCollectionItemImageDetail;
import com.pulumi.oci.Dblm.outputs.GetPatchManagementDatabasesPatchDatabasesCollectionItemPatchActivityDetail;
import com.pulumi.oci.Dblm.outputs.GetPatchManagementDatabasesPatchDatabasesCollectionItemPatchComplianceDetail;
import com.pulumi.oci.Dblm.outputs.GetPatchManagementDatabasesPatchDatabasesCollectionItemVulnerabilitiesSummary;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetPatchManagementDatabasesPatchDatabasesCollectionItem {
    /**
     * @return List of additional patches on database.
     * 
     */
    private List<GetPatchManagementDatabasesPatchDatabasesCollectionItemAdditionalPatch> additionalPatches;
    /**
     * @return This is the hashcode representing the list of patches applied.
     * 
     */
    private String currentPatchWatermark;
    /**
     * @return Database ocid.
     * 
     */
    private String databaseId;
    /**
     * @return Database name.
     * 
     */
    private String databaseName;
    /**
     * @return Filter by database type. Possible values Single Instance or RAC.
     * 
     */
    private String databaseType;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,String> definedTags;
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,String> freeformTags;
    /**
     * @return For SI, hosted on host and for RAC, host on cluster.
     * 
     */
    private String hostOrCluster;
    /**
     * @return Image details containing the subscribed image, its status, version, owner and time of creation.
     * 
     */
    private List<GetPatchManagementDatabasesPatchDatabasesCollectionItemImageDetail> imageDetails;
    /**
     * @return Path to the Oracle home.
     * 
     */
    private String oracleHomePath;
    /**
     * @return Details of deploy, update and migrate-listener(only for single Instance database) operations for this resource.
     * 
     */
    private List<GetPatchManagementDatabasesPatchDatabasesCollectionItemPatchActivityDetail> patchActivityDetails;
    /**
     * @return Patch Compliance Status
     * 
     */
    private List<GetPatchManagementDatabasesPatchDatabasesCollectionItemPatchComplianceDetail> patchComplianceDetails;
    /**
     * @return Intermediate user to be used for patching, created and maintained by customers. This user requires sudo access to switch as Oracle home owner and root user
     * 
     */
    private String patchUser;
    /**
     * @return Database release.
     * 
     */
    private String release;
    /**
     * @return Database release full version.
     * 
     */
    private String releaseFullVersion;
    /**
     * @return A filter to return only resources their lifecycleState matches the given lifecycleState.
     * 
     */
    private String state;
    /**
     * @return Path to sudo binary (executable) file
     * 
     */
    private String sudoFilePath;
    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    private Map<String,String> systemTags;
    /**
     * @return Summary of vulnerabilities found in registered resources grouped by severity.
     * 
     */
    private List<GetPatchManagementDatabasesPatchDatabasesCollectionItemVulnerabilitiesSummary> vulnerabilitiesSummaries;

    private GetPatchManagementDatabasesPatchDatabasesCollectionItem() {}
    /**
     * @return List of additional patches on database.
     * 
     */
    public List<GetPatchManagementDatabasesPatchDatabasesCollectionItemAdditionalPatch> additionalPatches() {
        return this.additionalPatches;
    }
    /**
     * @return This is the hashcode representing the list of patches applied.
     * 
     */
    public String currentPatchWatermark() {
        return this.currentPatchWatermark;
    }
    /**
     * @return Database ocid.
     * 
     */
    public String databaseId() {
        return this.databaseId;
    }
    /**
     * @return Database name.
     * 
     */
    public String databaseName() {
        return this.databaseName;
    }
    /**
     * @return Filter by database type. Possible values Single Instance or RAC.
     * 
     */
    public String databaseType() {
        return this.databaseType;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,String> definedTags() {
        return this.definedTags;
    }
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,String> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return For SI, hosted on host and for RAC, host on cluster.
     * 
     */
    public String hostOrCluster() {
        return this.hostOrCluster;
    }
    /**
     * @return Image details containing the subscribed image, its status, version, owner and time of creation.
     * 
     */
    public List<GetPatchManagementDatabasesPatchDatabasesCollectionItemImageDetail> imageDetails() {
        return this.imageDetails;
    }
    /**
     * @return Path to the Oracle home.
     * 
     */
    public String oracleHomePath() {
        return this.oracleHomePath;
    }
    /**
     * @return Details of deploy, update and migrate-listener(only for single Instance database) operations for this resource.
     * 
     */
    public List<GetPatchManagementDatabasesPatchDatabasesCollectionItemPatchActivityDetail> patchActivityDetails() {
        return this.patchActivityDetails;
    }
    /**
     * @return Patch Compliance Status
     * 
     */
    public List<GetPatchManagementDatabasesPatchDatabasesCollectionItemPatchComplianceDetail> patchComplianceDetails() {
        return this.patchComplianceDetails;
    }
    /**
     * @return Intermediate user to be used for patching, created and maintained by customers. This user requires sudo access to switch as Oracle home owner and root user
     * 
     */
    public String patchUser() {
        return this.patchUser;
    }
    /**
     * @return Database release.
     * 
     */
    public String release() {
        return this.release;
    }
    /**
     * @return Database release full version.
     * 
     */
    public String releaseFullVersion() {
        return this.releaseFullVersion;
    }
    /**
     * @return A filter to return only resources their lifecycleState matches the given lifecycleState.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return Path to sudo binary (executable) file
     * 
     */
    public String sudoFilePath() {
        return this.sudoFilePath;
    }
    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Map<String,String> systemTags() {
        return this.systemTags;
    }
    /**
     * @return Summary of vulnerabilities found in registered resources grouped by severity.
     * 
     */
    public List<GetPatchManagementDatabasesPatchDatabasesCollectionItemVulnerabilitiesSummary> vulnerabilitiesSummaries() {
        return this.vulnerabilitiesSummaries;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetPatchManagementDatabasesPatchDatabasesCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetPatchManagementDatabasesPatchDatabasesCollectionItemAdditionalPatch> additionalPatches;
        private String currentPatchWatermark;
        private String databaseId;
        private String databaseName;
        private String databaseType;
        private Map<String,String> definedTags;
        private Map<String,String> freeformTags;
        private String hostOrCluster;
        private List<GetPatchManagementDatabasesPatchDatabasesCollectionItemImageDetail> imageDetails;
        private String oracleHomePath;
        private List<GetPatchManagementDatabasesPatchDatabasesCollectionItemPatchActivityDetail> patchActivityDetails;
        private List<GetPatchManagementDatabasesPatchDatabasesCollectionItemPatchComplianceDetail> patchComplianceDetails;
        private String patchUser;
        private String release;
        private String releaseFullVersion;
        private String state;
        private String sudoFilePath;
        private Map<String,String> systemTags;
        private List<GetPatchManagementDatabasesPatchDatabasesCollectionItemVulnerabilitiesSummary> vulnerabilitiesSummaries;
        public Builder() {}
        public Builder(GetPatchManagementDatabasesPatchDatabasesCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.additionalPatches = defaults.additionalPatches;
    	      this.currentPatchWatermark = defaults.currentPatchWatermark;
    	      this.databaseId = defaults.databaseId;
    	      this.databaseName = defaults.databaseName;
    	      this.databaseType = defaults.databaseType;
    	      this.definedTags = defaults.definedTags;
    	      this.freeformTags = defaults.freeformTags;
    	      this.hostOrCluster = defaults.hostOrCluster;
    	      this.imageDetails = defaults.imageDetails;
    	      this.oracleHomePath = defaults.oracleHomePath;
    	      this.patchActivityDetails = defaults.patchActivityDetails;
    	      this.patchComplianceDetails = defaults.patchComplianceDetails;
    	      this.patchUser = defaults.patchUser;
    	      this.release = defaults.release;
    	      this.releaseFullVersion = defaults.releaseFullVersion;
    	      this.state = defaults.state;
    	      this.sudoFilePath = defaults.sudoFilePath;
    	      this.systemTags = defaults.systemTags;
    	      this.vulnerabilitiesSummaries = defaults.vulnerabilitiesSummaries;
        }

        @CustomType.Setter
        public Builder additionalPatches(List<GetPatchManagementDatabasesPatchDatabasesCollectionItemAdditionalPatch> additionalPatches) {
            if (additionalPatches == null) {
              throw new MissingRequiredPropertyException("GetPatchManagementDatabasesPatchDatabasesCollectionItem", "additionalPatches");
            }
            this.additionalPatches = additionalPatches;
            return this;
        }
        public Builder additionalPatches(GetPatchManagementDatabasesPatchDatabasesCollectionItemAdditionalPatch... additionalPatches) {
            return additionalPatches(List.of(additionalPatches));
        }
        @CustomType.Setter
        public Builder currentPatchWatermark(String currentPatchWatermark) {
            if (currentPatchWatermark == null) {
              throw new MissingRequiredPropertyException("GetPatchManagementDatabasesPatchDatabasesCollectionItem", "currentPatchWatermark");
            }
            this.currentPatchWatermark = currentPatchWatermark;
            return this;
        }
        @CustomType.Setter
        public Builder databaseId(String databaseId) {
            if (databaseId == null) {
              throw new MissingRequiredPropertyException("GetPatchManagementDatabasesPatchDatabasesCollectionItem", "databaseId");
            }
            this.databaseId = databaseId;
            return this;
        }
        @CustomType.Setter
        public Builder databaseName(String databaseName) {
            if (databaseName == null) {
              throw new MissingRequiredPropertyException("GetPatchManagementDatabasesPatchDatabasesCollectionItem", "databaseName");
            }
            this.databaseName = databaseName;
            return this;
        }
        @CustomType.Setter
        public Builder databaseType(String databaseType) {
            if (databaseType == null) {
              throw new MissingRequiredPropertyException("GetPatchManagementDatabasesPatchDatabasesCollectionItem", "databaseType");
            }
            this.databaseType = databaseType;
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,String> definedTags) {
            if (definedTags == null) {
              throw new MissingRequiredPropertyException("GetPatchManagementDatabasesPatchDatabasesCollectionItem", "definedTags");
            }
            this.definedTags = definedTags;
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,String> freeformTags) {
            if (freeformTags == null) {
              throw new MissingRequiredPropertyException("GetPatchManagementDatabasesPatchDatabasesCollectionItem", "freeformTags");
            }
            this.freeformTags = freeformTags;
            return this;
        }
        @CustomType.Setter
        public Builder hostOrCluster(String hostOrCluster) {
            if (hostOrCluster == null) {
              throw new MissingRequiredPropertyException("GetPatchManagementDatabasesPatchDatabasesCollectionItem", "hostOrCluster");
            }
            this.hostOrCluster = hostOrCluster;
            return this;
        }
        @CustomType.Setter
        public Builder imageDetails(List<GetPatchManagementDatabasesPatchDatabasesCollectionItemImageDetail> imageDetails) {
            if (imageDetails == null) {
              throw new MissingRequiredPropertyException("GetPatchManagementDatabasesPatchDatabasesCollectionItem", "imageDetails");
            }
            this.imageDetails = imageDetails;
            return this;
        }
        public Builder imageDetails(GetPatchManagementDatabasesPatchDatabasesCollectionItemImageDetail... imageDetails) {
            return imageDetails(List.of(imageDetails));
        }
        @CustomType.Setter
        public Builder oracleHomePath(String oracleHomePath) {
            if (oracleHomePath == null) {
              throw new MissingRequiredPropertyException("GetPatchManagementDatabasesPatchDatabasesCollectionItem", "oracleHomePath");
            }
            this.oracleHomePath = oracleHomePath;
            return this;
        }
        @CustomType.Setter
        public Builder patchActivityDetails(List<GetPatchManagementDatabasesPatchDatabasesCollectionItemPatchActivityDetail> patchActivityDetails) {
            if (patchActivityDetails == null) {
              throw new MissingRequiredPropertyException("GetPatchManagementDatabasesPatchDatabasesCollectionItem", "patchActivityDetails");
            }
            this.patchActivityDetails = patchActivityDetails;
            return this;
        }
        public Builder patchActivityDetails(GetPatchManagementDatabasesPatchDatabasesCollectionItemPatchActivityDetail... patchActivityDetails) {
            return patchActivityDetails(List.of(patchActivityDetails));
        }
        @CustomType.Setter
        public Builder patchComplianceDetails(List<GetPatchManagementDatabasesPatchDatabasesCollectionItemPatchComplianceDetail> patchComplianceDetails) {
            if (patchComplianceDetails == null) {
              throw new MissingRequiredPropertyException("GetPatchManagementDatabasesPatchDatabasesCollectionItem", "patchComplianceDetails");
            }
            this.patchComplianceDetails = patchComplianceDetails;
            return this;
        }
        public Builder patchComplianceDetails(GetPatchManagementDatabasesPatchDatabasesCollectionItemPatchComplianceDetail... patchComplianceDetails) {
            return patchComplianceDetails(List.of(patchComplianceDetails));
        }
        @CustomType.Setter
        public Builder patchUser(String patchUser) {
            if (patchUser == null) {
              throw new MissingRequiredPropertyException("GetPatchManagementDatabasesPatchDatabasesCollectionItem", "patchUser");
            }
            this.patchUser = patchUser;
            return this;
        }
        @CustomType.Setter
        public Builder release(String release) {
            if (release == null) {
              throw new MissingRequiredPropertyException("GetPatchManagementDatabasesPatchDatabasesCollectionItem", "release");
            }
            this.release = release;
            return this;
        }
        @CustomType.Setter
        public Builder releaseFullVersion(String releaseFullVersion) {
            if (releaseFullVersion == null) {
              throw new MissingRequiredPropertyException("GetPatchManagementDatabasesPatchDatabasesCollectionItem", "releaseFullVersion");
            }
            this.releaseFullVersion = releaseFullVersion;
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetPatchManagementDatabasesPatchDatabasesCollectionItem", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder sudoFilePath(String sudoFilePath) {
            if (sudoFilePath == null) {
              throw new MissingRequiredPropertyException("GetPatchManagementDatabasesPatchDatabasesCollectionItem", "sudoFilePath");
            }
            this.sudoFilePath = sudoFilePath;
            return this;
        }
        @CustomType.Setter
        public Builder systemTags(Map<String,String> systemTags) {
            if (systemTags == null) {
              throw new MissingRequiredPropertyException("GetPatchManagementDatabasesPatchDatabasesCollectionItem", "systemTags");
            }
            this.systemTags = systemTags;
            return this;
        }
        @CustomType.Setter
        public Builder vulnerabilitiesSummaries(List<GetPatchManagementDatabasesPatchDatabasesCollectionItemVulnerabilitiesSummary> vulnerabilitiesSummaries) {
            if (vulnerabilitiesSummaries == null) {
              throw new MissingRequiredPropertyException("GetPatchManagementDatabasesPatchDatabasesCollectionItem", "vulnerabilitiesSummaries");
            }
            this.vulnerabilitiesSummaries = vulnerabilitiesSummaries;
            return this;
        }
        public Builder vulnerabilitiesSummaries(GetPatchManagementDatabasesPatchDatabasesCollectionItemVulnerabilitiesSummary... vulnerabilitiesSummaries) {
            return vulnerabilitiesSummaries(List.of(vulnerabilitiesSummaries));
        }
        public GetPatchManagementDatabasesPatchDatabasesCollectionItem build() {
            final var _resultValue = new GetPatchManagementDatabasesPatchDatabasesCollectionItem();
            _resultValue.additionalPatches = additionalPatches;
            _resultValue.currentPatchWatermark = currentPatchWatermark;
            _resultValue.databaseId = databaseId;
            _resultValue.databaseName = databaseName;
            _resultValue.databaseType = databaseType;
            _resultValue.definedTags = definedTags;
            _resultValue.freeformTags = freeformTags;
            _resultValue.hostOrCluster = hostOrCluster;
            _resultValue.imageDetails = imageDetails;
            _resultValue.oracleHomePath = oracleHomePath;
            _resultValue.patchActivityDetails = patchActivityDetails;
            _resultValue.patchComplianceDetails = patchComplianceDetails;
            _resultValue.patchUser = patchUser;
            _resultValue.release = release;
            _resultValue.releaseFullVersion = releaseFullVersion;
            _resultValue.state = state;
            _resultValue.sudoFilePath = sudoFilePath;
            _resultValue.systemTags = systemTags;
            _resultValue.vulnerabilitiesSummaries = vulnerabilitiesSummaries;
            return _resultValue;
        }
    }
}
