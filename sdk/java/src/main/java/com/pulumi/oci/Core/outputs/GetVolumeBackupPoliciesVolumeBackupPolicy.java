// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Core.outputs.GetVolumeBackupPoliciesVolumeBackupPolicySchedule;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetVolumeBackupPoliciesVolumeBackupPolicy {
    /**
     * @return The OCID of the compartment. If no compartment is specified, the Oracle defined backup policies are listed.
     * 
     */
    private String compartmentId;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    private Map<String,Object> definedTags;
    /**
     * @return The paired destination region for copying scheduled backups to. Example `us-ashburn-1`. See [Region Pairs](https://docs.cloud.oracle.com/iaas/Content/Block/Tasks/schedulingvolumebackups.htm#RegionPairs) for details about paired regions.
     * 
     */
    private String destinationRegion;
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    private String displayName;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private Map<String,Object> freeformTags;
    /**
     * @return The OCID of the volume backup policy.
     * 
     */
    private String id;
    /**
     * @return The collection of schedules that this policy will apply.
     * 
     */
    private List<GetVolumeBackupPoliciesVolumeBackupPolicySchedule> schedules;
    /**
     * @return The date and time the volume backup policy was created. Format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    private String timeCreated;

    private GetVolumeBackupPoliciesVolumeBackupPolicy() {}
    /**
     * @return The OCID of the compartment. If no compartment is specified, the Oracle defined backup policies are listed.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Map<String,Object> definedTags() {
        return this.definedTags;
    }
    /**
     * @return The paired destination region for copying scheduled backups to. Example `us-ashburn-1`. See [Region Pairs](https://docs.cloud.oracle.com/iaas/Content/Block/Tasks/schedulingvolumebackups.htm#RegionPairs) for details about paired regions.
     * 
     */
    public String destinationRegion() {
        return this.destinationRegion;
    }
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Map<String,Object> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The OCID of the volume backup policy.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The collection of schedules that this policy will apply.
     * 
     */
    public List<GetVolumeBackupPoliciesVolumeBackupPolicySchedule> schedules() {
        return this.schedules;
    }
    /**
     * @return The date and time the volume backup policy was created. Format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetVolumeBackupPoliciesVolumeBackupPolicy defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private Map<String,Object> definedTags;
        private String destinationRegion;
        private String displayName;
        private Map<String,Object> freeformTags;
        private String id;
        private List<GetVolumeBackupPoliciesVolumeBackupPolicySchedule> schedules;
        private String timeCreated;
        public Builder() {}
        public Builder(GetVolumeBackupPoliciesVolumeBackupPolicy defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.definedTags = defaults.definedTags;
    	      this.destinationRegion = defaults.destinationRegion;
    	      this.displayName = defaults.displayName;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.schedules = defaults.schedules;
    	      this.timeCreated = defaults.timeCreated;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,Object> definedTags) {
            this.definedTags = Objects.requireNonNull(definedTags);
            return this;
        }
        @CustomType.Setter
        public Builder destinationRegion(String destinationRegion) {
            this.destinationRegion = Objects.requireNonNull(destinationRegion);
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            this.displayName = Objects.requireNonNull(displayName);
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,Object> freeformTags) {
            this.freeformTags = Objects.requireNonNull(freeformTags);
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder schedules(List<GetVolumeBackupPoliciesVolumeBackupPolicySchedule> schedules) {
            this.schedules = Objects.requireNonNull(schedules);
            return this;
        }
        public Builder schedules(GetVolumeBackupPoliciesVolumeBackupPolicySchedule... schedules) {
            return schedules(List.of(schedules));
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }
        public GetVolumeBackupPoliciesVolumeBackupPolicy build() {
            final var o = new GetVolumeBackupPoliciesVolumeBackupPolicy();
            o.compartmentId = compartmentId;
            o.definedTags = definedTags;
            o.destinationRegion = destinationRegion;
            o.displayName = displayName;
            o.freeformTags = freeformTags;
            o.id = id;
            o.schedules = schedules;
            o.timeCreated = timeCreated;
            return o;
        }
    }
}