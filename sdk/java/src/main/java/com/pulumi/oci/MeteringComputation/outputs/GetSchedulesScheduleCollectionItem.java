// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.MeteringComputation.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.MeteringComputation.outputs.GetSchedulesScheduleCollectionItemQueryProperty;
import com.pulumi.oci.MeteringComputation.outputs.GetSchedulesScheduleCollectionItemResultLocation;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetSchedulesScheduleCollectionItem {
    /**
     * @return The compartment ID in which to list resources.
     * 
     */
    private String compartmentId;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,Object> definedTags;
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,Object> freeformTags;
    /**
     * @return The OCID representing unique shedule
     * 
     */
    private String id;
    /**
     * @return Query parameter for filtering by name
     * 
     */
    private String name;
    /**
     * @return The query properties.
     * 
     */
    private List<GetSchedulesScheduleCollectionItemQueryProperty> queryProperties;
    /**
     * @return The location where usage/cost CSVs will be uploaded defined by `locationType`, which corresponds with type-specific characteristics.
     * 
     */
    private List<GetSchedulesScheduleCollectionItemResultLocation> resultLocations;
    /**
     * @return In x-obmcs-recurring-time format shown here: https://datatracker.ietf.org/doc/html/rfc5545#section-3.3.10 Describes the frequency of when the schedule will be run
     * 
     */
    private String scheduleRecurrences;
    /**
     * @return The lifecycle state of the schedule
     * 
     */
    private String state;
    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    private Map<String,Object> systemTags;
    /**
     * @return The date and time of when the schedule was created
     * 
     */
    private String timeCreated;
    /**
     * @return The date and time of the first time job execution
     * 
     */
    private String timeScheduled;

    private GetSchedulesScheduleCollectionItem() {}
    /**
     * @return The compartment ID in which to list resources.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,Object> definedTags() {
        return this.definedTags;
    }
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,Object> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The OCID representing unique shedule
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Query parameter for filtering by name
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return The query properties.
     * 
     */
    public List<GetSchedulesScheduleCollectionItemQueryProperty> queryProperties() {
        return this.queryProperties;
    }
    /**
     * @return The location where usage/cost CSVs will be uploaded defined by `locationType`, which corresponds with type-specific characteristics.
     * 
     */
    public List<GetSchedulesScheduleCollectionItemResultLocation> resultLocations() {
        return this.resultLocations;
    }
    /**
     * @return In x-obmcs-recurring-time format shown here: https://datatracker.ietf.org/doc/html/rfc5545#section-3.3.10 Describes the frequency of when the schedule will be run
     * 
     */
    public String scheduleRecurrences() {
        return this.scheduleRecurrences;
    }
    /**
     * @return The lifecycle state of the schedule
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Map<String,Object> systemTags() {
        return this.systemTags;
    }
    /**
     * @return The date and time of when the schedule was created
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The date and time of the first time job execution
     * 
     */
    public String timeScheduled() {
        return this.timeScheduled;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetSchedulesScheduleCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private Map<String,Object> definedTags;
        private Map<String,Object> freeformTags;
        private String id;
        private String name;
        private List<GetSchedulesScheduleCollectionItemQueryProperty> queryProperties;
        private List<GetSchedulesScheduleCollectionItemResultLocation> resultLocations;
        private String scheduleRecurrences;
        private String state;
        private Map<String,Object> systemTags;
        private String timeCreated;
        private String timeScheduled;
        public Builder() {}
        public Builder(GetSchedulesScheduleCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.definedTags = defaults.definedTags;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.name = defaults.name;
    	      this.queryProperties = defaults.queryProperties;
    	      this.resultLocations = defaults.resultLocations;
    	      this.scheduleRecurrences = defaults.scheduleRecurrences;
    	      this.state = defaults.state;
    	      this.systemTags = defaults.systemTags;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeScheduled = defaults.timeScheduled;
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
        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }
        @CustomType.Setter
        public Builder queryProperties(List<GetSchedulesScheduleCollectionItemQueryProperty> queryProperties) {
            this.queryProperties = Objects.requireNonNull(queryProperties);
            return this;
        }
        public Builder queryProperties(GetSchedulesScheduleCollectionItemQueryProperty... queryProperties) {
            return queryProperties(List.of(queryProperties));
        }
        @CustomType.Setter
        public Builder resultLocations(List<GetSchedulesScheduleCollectionItemResultLocation> resultLocations) {
            this.resultLocations = Objects.requireNonNull(resultLocations);
            return this;
        }
        public Builder resultLocations(GetSchedulesScheduleCollectionItemResultLocation... resultLocations) {
            return resultLocations(List.of(resultLocations));
        }
        @CustomType.Setter
        public Builder scheduleRecurrences(String scheduleRecurrences) {
            this.scheduleRecurrences = Objects.requireNonNull(scheduleRecurrences);
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }
        @CustomType.Setter
        public Builder systemTags(Map<String,Object> systemTags) {
            this.systemTags = Objects.requireNonNull(systemTags);
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }
        @CustomType.Setter
        public Builder timeScheduled(String timeScheduled) {
            this.timeScheduled = Objects.requireNonNull(timeScheduled);
            return this;
        }
        public GetSchedulesScheduleCollectionItem build() {
            final var o = new GetSchedulesScheduleCollectionItem();
            o.compartmentId = compartmentId;
            o.definedTags = definedTags;
            o.freeformTags = freeformTags;
            o.id = id;
            o.name = name;
            o.queryProperties = queryProperties;
            o.resultLocations = resultLocations;
            o.scheduleRecurrences = scheduleRecurrences;
            o.state = state;
            o.systemTags = systemTags;
            o.timeCreated = timeCreated;
            o.timeScheduled = timeScheduled;
            return o;
        }
    }
}