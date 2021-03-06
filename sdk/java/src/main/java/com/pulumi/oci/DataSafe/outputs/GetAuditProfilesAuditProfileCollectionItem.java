// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DataSafe.outputs.GetAuditProfilesAuditProfileCollectionItemAuditTrail;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetAuditProfilesAuditProfileCollectionItem {
    /**
     * @return Indicates number of audit records collected by Data Safe in the current calendar month.  Audit records for the Data Safe service account are excluded and are not counted towards your monthly free limit.
     * 
     */
    private final String auditCollectedVolume;
    /**
     * @return A optional filter to return only resources that match the specified id.
     * 
     */
    private final String auditProfileId;
    /**
     * @return Indicates the list of available audit trails on the target.
     * 
     */
    private final List<GetAuditProfilesAuditProfileCollectionItemAuditTrail> auditTrails;
    private final Integer changeRetentionTrigger;
    /**
     * @return A filter to return only resources that match the specified compartment OCID.
     * 
     */
    private final String compartmentId;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    private final Map<String,Object> definedTags;
    /**
     * @return The description of the audit profile.
     * 
     */
    private final String description;
    /**
     * @return A filter to return only resources that match the specified display name.
     * 
     */
    private final String displayName;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private final Map<String,Object> freeformTags;
    /**
     * @return The OCID of the audit profile.
     * 
     */
    private final String id;
    /**
     * @return A optional filter to return only resources that match the specified retention configured value.
     * 
     */
    private final Boolean isOverrideGlobalRetentionSetting;
    /**
     * @return Indicates if you want to continue audit record collection beyond the free limit of one million audit records per month per target database, incurring additional charges. The default value is inherited from the global settings. You can change at the global level or at the target level.
     * 
     */
    private final Boolean isPaidUsageEnabled;
    /**
     * @return Details about the current state of the audit profile in Data Safe.
     * 
     */
    private final String lifecycleDetails;
    /**
     * @return Indicates the number of months the audit records will be stored offline in the Data Safe audit archive. Minimum: 0; Maximum: 72 months. If you have a requirement to store the audit data even longer in archive, please contact the Oracle Support.
     * 
     */
    private final Integer offlineMonths;
    /**
     * @return Indicates the number of months the audit records will be stored online in Oracle Data Safe audit repository for immediate reporting and analysis.  Minimum: 1; Maximum:12 months
     * 
     */
    private final Integer onlineMonths;
    /**
     * @return A optional filter to return only resources that match the specified lifecycle state.
     * 
     */
    private final String state;
    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    private final Map<String,Object> systemTags;
    /**
     * @return A filter to return only items related to a specific target OCID.
     * 
     */
    private final String targetId;
    /**
     * @return The date and time the audit profile was created, in the format defined by RFC3339.
     * 
     */
    private final String timeCreated;
    /**
     * @return The date and time the audit profile was updated, in the format defined by RFC3339.
     * 
     */
    private final String timeUpdated;

    @CustomType.Constructor
    private GetAuditProfilesAuditProfileCollectionItem(
        @CustomType.Parameter("auditCollectedVolume") String auditCollectedVolume,
        @CustomType.Parameter("auditProfileId") String auditProfileId,
        @CustomType.Parameter("auditTrails") List<GetAuditProfilesAuditProfileCollectionItemAuditTrail> auditTrails,
        @CustomType.Parameter("changeRetentionTrigger") Integer changeRetentionTrigger,
        @CustomType.Parameter("compartmentId") String compartmentId,
        @CustomType.Parameter("definedTags") Map<String,Object> definedTags,
        @CustomType.Parameter("description") String description,
        @CustomType.Parameter("displayName") String displayName,
        @CustomType.Parameter("freeformTags") Map<String,Object> freeformTags,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("isOverrideGlobalRetentionSetting") Boolean isOverrideGlobalRetentionSetting,
        @CustomType.Parameter("isPaidUsageEnabled") Boolean isPaidUsageEnabled,
        @CustomType.Parameter("lifecycleDetails") String lifecycleDetails,
        @CustomType.Parameter("offlineMonths") Integer offlineMonths,
        @CustomType.Parameter("onlineMonths") Integer onlineMonths,
        @CustomType.Parameter("state") String state,
        @CustomType.Parameter("systemTags") Map<String,Object> systemTags,
        @CustomType.Parameter("targetId") String targetId,
        @CustomType.Parameter("timeCreated") String timeCreated,
        @CustomType.Parameter("timeUpdated") String timeUpdated) {
        this.auditCollectedVolume = auditCollectedVolume;
        this.auditProfileId = auditProfileId;
        this.auditTrails = auditTrails;
        this.changeRetentionTrigger = changeRetentionTrigger;
        this.compartmentId = compartmentId;
        this.definedTags = definedTags;
        this.description = description;
        this.displayName = displayName;
        this.freeformTags = freeformTags;
        this.id = id;
        this.isOverrideGlobalRetentionSetting = isOverrideGlobalRetentionSetting;
        this.isPaidUsageEnabled = isPaidUsageEnabled;
        this.lifecycleDetails = lifecycleDetails;
        this.offlineMonths = offlineMonths;
        this.onlineMonths = onlineMonths;
        this.state = state;
        this.systemTags = systemTags;
        this.targetId = targetId;
        this.timeCreated = timeCreated;
        this.timeUpdated = timeUpdated;
    }

    /**
     * @return Indicates number of audit records collected by Data Safe in the current calendar month.  Audit records for the Data Safe service account are excluded and are not counted towards your monthly free limit.
     * 
     */
    public String auditCollectedVolume() {
        return this.auditCollectedVolume;
    }
    /**
     * @return A optional filter to return only resources that match the specified id.
     * 
     */
    public String auditProfileId() {
        return this.auditProfileId;
    }
    /**
     * @return Indicates the list of available audit trails on the target.
     * 
     */
    public List<GetAuditProfilesAuditProfileCollectionItemAuditTrail> auditTrails() {
        return this.auditTrails;
    }
    public Integer changeRetentionTrigger() {
        return this.changeRetentionTrigger;
    }
    /**
     * @return A filter to return only resources that match the specified compartment OCID.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Map<String,Object> definedTags() {
        return this.definedTags;
    }
    /**
     * @return The description of the audit profile.
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return A filter to return only resources that match the specified display name.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Map<String,Object> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The OCID of the audit profile.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return A optional filter to return only resources that match the specified retention configured value.
     * 
     */
    public Boolean isOverrideGlobalRetentionSetting() {
        return this.isOverrideGlobalRetentionSetting;
    }
    /**
     * @return Indicates if you want to continue audit record collection beyond the free limit of one million audit records per month per target database, incurring additional charges. The default value is inherited from the global settings. You can change at the global level or at the target level.
     * 
     */
    public Boolean isPaidUsageEnabled() {
        return this.isPaidUsageEnabled;
    }
    /**
     * @return Details about the current state of the audit profile in Data Safe.
     * 
     */
    public String lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * @return Indicates the number of months the audit records will be stored offline in the Data Safe audit archive. Minimum: 0; Maximum: 72 months. If you have a requirement to store the audit data even longer in archive, please contact the Oracle Support.
     * 
     */
    public Integer offlineMonths() {
        return this.offlineMonths;
    }
    /**
     * @return Indicates the number of months the audit records will be stored online in Oracle Data Safe audit repository for immediate reporting and analysis.  Minimum: 1; Maximum:12 months
     * 
     */
    public Integer onlineMonths() {
        return this.onlineMonths;
    }
    /**
     * @return A optional filter to return only resources that match the specified lifecycle state.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Map<String,Object> systemTags() {
        return this.systemTags;
    }
    /**
     * @return A filter to return only items related to a specific target OCID.
     * 
     */
    public String targetId() {
        return this.targetId;
    }
    /**
     * @return The date and time the audit profile was created, in the format defined by RFC3339.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The date and time the audit profile was updated, in the format defined by RFC3339.
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAuditProfilesAuditProfileCollectionItem defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String auditCollectedVolume;
        private String auditProfileId;
        private List<GetAuditProfilesAuditProfileCollectionItemAuditTrail> auditTrails;
        private Integer changeRetentionTrigger;
        private String compartmentId;
        private Map<String,Object> definedTags;
        private String description;
        private String displayName;
        private Map<String,Object> freeformTags;
        private String id;
        private Boolean isOverrideGlobalRetentionSetting;
        private Boolean isPaidUsageEnabled;
        private String lifecycleDetails;
        private Integer offlineMonths;
        private Integer onlineMonths;
        private String state;
        private Map<String,Object> systemTags;
        private String targetId;
        private String timeCreated;
        private String timeUpdated;

        public Builder() {
    	      // Empty
        }

        public Builder(GetAuditProfilesAuditProfileCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.auditCollectedVolume = defaults.auditCollectedVolume;
    	      this.auditProfileId = defaults.auditProfileId;
    	      this.auditTrails = defaults.auditTrails;
    	      this.changeRetentionTrigger = defaults.changeRetentionTrigger;
    	      this.compartmentId = defaults.compartmentId;
    	      this.definedTags = defaults.definedTags;
    	      this.description = defaults.description;
    	      this.displayName = defaults.displayName;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.isOverrideGlobalRetentionSetting = defaults.isOverrideGlobalRetentionSetting;
    	      this.isPaidUsageEnabled = defaults.isPaidUsageEnabled;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.offlineMonths = defaults.offlineMonths;
    	      this.onlineMonths = defaults.onlineMonths;
    	      this.state = defaults.state;
    	      this.systemTags = defaults.systemTags;
    	      this.targetId = defaults.targetId;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
        }

        public Builder auditCollectedVolume(String auditCollectedVolume) {
            this.auditCollectedVolume = Objects.requireNonNull(auditCollectedVolume);
            return this;
        }
        public Builder auditProfileId(String auditProfileId) {
            this.auditProfileId = Objects.requireNonNull(auditProfileId);
            return this;
        }
        public Builder auditTrails(List<GetAuditProfilesAuditProfileCollectionItemAuditTrail> auditTrails) {
            this.auditTrails = Objects.requireNonNull(auditTrails);
            return this;
        }
        public Builder auditTrails(GetAuditProfilesAuditProfileCollectionItemAuditTrail... auditTrails) {
            return auditTrails(List.of(auditTrails));
        }
        public Builder changeRetentionTrigger(Integer changeRetentionTrigger) {
            this.changeRetentionTrigger = Objects.requireNonNull(changeRetentionTrigger);
            return this;
        }
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        public Builder definedTags(Map<String,Object> definedTags) {
            this.definedTags = Objects.requireNonNull(definedTags);
            return this;
        }
        public Builder description(String description) {
            this.description = Objects.requireNonNull(description);
            return this;
        }
        public Builder displayName(String displayName) {
            this.displayName = Objects.requireNonNull(displayName);
            return this;
        }
        public Builder freeformTags(Map<String,Object> freeformTags) {
            this.freeformTags = Objects.requireNonNull(freeformTags);
            return this;
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder isOverrideGlobalRetentionSetting(Boolean isOverrideGlobalRetentionSetting) {
            this.isOverrideGlobalRetentionSetting = Objects.requireNonNull(isOverrideGlobalRetentionSetting);
            return this;
        }
        public Builder isPaidUsageEnabled(Boolean isPaidUsageEnabled) {
            this.isPaidUsageEnabled = Objects.requireNonNull(isPaidUsageEnabled);
            return this;
        }
        public Builder lifecycleDetails(String lifecycleDetails) {
            this.lifecycleDetails = Objects.requireNonNull(lifecycleDetails);
            return this;
        }
        public Builder offlineMonths(Integer offlineMonths) {
            this.offlineMonths = Objects.requireNonNull(offlineMonths);
            return this;
        }
        public Builder onlineMonths(Integer onlineMonths) {
            this.onlineMonths = Objects.requireNonNull(onlineMonths);
            return this;
        }
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }
        public Builder systemTags(Map<String,Object> systemTags) {
            this.systemTags = Objects.requireNonNull(systemTags);
            return this;
        }
        public Builder targetId(String targetId) {
            this.targetId = Objects.requireNonNull(targetId);
            return this;
        }
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }
        public Builder timeUpdated(String timeUpdated) {
            this.timeUpdated = Objects.requireNonNull(timeUpdated);
            return this;
        }        public GetAuditProfilesAuditProfileCollectionItem build() {
            return new GetAuditProfilesAuditProfileCollectionItem(auditCollectedVolume, auditProfileId, auditTrails, changeRetentionTrigger, compartmentId, definedTags, description, displayName, freeformTags, id, isOverrideGlobalRetentionSetting, isPaidUsageEnabled, lifecycleDetails, offlineMonths, onlineMonths, state, systemTags, targetId, timeCreated, timeUpdated);
        }
    }
}
