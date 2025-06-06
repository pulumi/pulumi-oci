// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LogAnalytics.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.LogAnalytics.outputs.GetNamespaceScheduledTaskActionMetricExtraction;
import com.pulumi.oci.LogAnalytics.outputs.GetNamespaceScheduledTaskActionTemplateDetail;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetNamespaceScheduledTaskAction {
    /**
     * @return if true, purge child compartments data
     * 
     */
    private Boolean compartmentIdInSubtree;
    /**
     * @return the type of the log data to be purged
     * 
     */
    private String dataType;
    /**
     * @return Specify metric extraction for SAVED_SEARCH scheduled task execution to post to Oracle Cloud Infrastructure Monitoring.
     * 
     */
    private List<GetNamespaceScheduledTaskActionMetricExtraction> metricExtractions;
    /**
     * @return the compartment OCID under which the data will be purged
     * 
     */
    private String purgeCompartmentId;
    /**
     * @return The duration of data to be retained, which is used to calculate the timeDataEnded when the task fires. The value should be negative. Purge duration in ISO 8601 extended format as described in https://en.wikipedia.org/wiki/ISO_8601#Durations. The largest supported unit is D, e.g. -P365D (not -P1Y) or -P14D (not -P2W).
     * 
     */
    private String purgeDuration;
    /**
     * @return Purge query string.
     * 
     */
    private String queryString;
    /**
     * @return The ManagementSavedSearch id [OCID] utilized in the action.
     * 
     */
    private String savedSearchId;
    /**
     * @return details for scheduled task using template
     * 
     */
    private List<GetNamespaceScheduledTaskActionTemplateDetail> templateDetails;
    /**
     * @return Schedule type discriminator.
     * 
     */
    private String type;

    private GetNamespaceScheduledTaskAction() {}
    /**
     * @return if true, purge child compartments data
     * 
     */
    public Boolean compartmentIdInSubtree() {
        return this.compartmentIdInSubtree;
    }
    /**
     * @return the type of the log data to be purged
     * 
     */
    public String dataType() {
        return this.dataType;
    }
    /**
     * @return Specify metric extraction for SAVED_SEARCH scheduled task execution to post to Oracle Cloud Infrastructure Monitoring.
     * 
     */
    public List<GetNamespaceScheduledTaskActionMetricExtraction> metricExtractions() {
        return this.metricExtractions;
    }
    /**
     * @return the compartment OCID under which the data will be purged
     * 
     */
    public String purgeCompartmentId() {
        return this.purgeCompartmentId;
    }
    /**
     * @return The duration of data to be retained, which is used to calculate the timeDataEnded when the task fires. The value should be negative. Purge duration in ISO 8601 extended format as described in https://en.wikipedia.org/wiki/ISO_8601#Durations. The largest supported unit is D, e.g. -P365D (not -P1Y) or -P14D (not -P2W).
     * 
     */
    public String purgeDuration() {
        return this.purgeDuration;
    }
    /**
     * @return Purge query string.
     * 
     */
    public String queryString() {
        return this.queryString;
    }
    /**
     * @return The ManagementSavedSearch id [OCID] utilized in the action.
     * 
     */
    public String savedSearchId() {
        return this.savedSearchId;
    }
    /**
     * @return details for scheduled task using template
     * 
     */
    public List<GetNamespaceScheduledTaskActionTemplateDetail> templateDetails() {
        return this.templateDetails;
    }
    /**
     * @return Schedule type discriminator.
     * 
     */
    public String type() {
        return this.type;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetNamespaceScheduledTaskAction defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Boolean compartmentIdInSubtree;
        private String dataType;
        private List<GetNamespaceScheduledTaskActionMetricExtraction> metricExtractions;
        private String purgeCompartmentId;
        private String purgeDuration;
        private String queryString;
        private String savedSearchId;
        private List<GetNamespaceScheduledTaskActionTemplateDetail> templateDetails;
        private String type;
        public Builder() {}
        public Builder(GetNamespaceScheduledTaskAction defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentIdInSubtree = defaults.compartmentIdInSubtree;
    	      this.dataType = defaults.dataType;
    	      this.metricExtractions = defaults.metricExtractions;
    	      this.purgeCompartmentId = defaults.purgeCompartmentId;
    	      this.purgeDuration = defaults.purgeDuration;
    	      this.queryString = defaults.queryString;
    	      this.savedSearchId = defaults.savedSearchId;
    	      this.templateDetails = defaults.templateDetails;
    	      this.type = defaults.type;
        }

        @CustomType.Setter
        public Builder compartmentIdInSubtree(Boolean compartmentIdInSubtree) {
            if (compartmentIdInSubtree == null) {
              throw new MissingRequiredPropertyException("GetNamespaceScheduledTaskAction", "compartmentIdInSubtree");
            }
            this.compartmentIdInSubtree = compartmentIdInSubtree;
            return this;
        }
        @CustomType.Setter
        public Builder dataType(String dataType) {
            if (dataType == null) {
              throw new MissingRequiredPropertyException("GetNamespaceScheduledTaskAction", "dataType");
            }
            this.dataType = dataType;
            return this;
        }
        @CustomType.Setter
        public Builder metricExtractions(List<GetNamespaceScheduledTaskActionMetricExtraction> metricExtractions) {
            if (metricExtractions == null) {
              throw new MissingRequiredPropertyException("GetNamespaceScheduledTaskAction", "metricExtractions");
            }
            this.metricExtractions = metricExtractions;
            return this;
        }
        public Builder metricExtractions(GetNamespaceScheduledTaskActionMetricExtraction... metricExtractions) {
            return metricExtractions(List.of(metricExtractions));
        }
        @CustomType.Setter
        public Builder purgeCompartmentId(String purgeCompartmentId) {
            if (purgeCompartmentId == null) {
              throw new MissingRequiredPropertyException("GetNamespaceScheduledTaskAction", "purgeCompartmentId");
            }
            this.purgeCompartmentId = purgeCompartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder purgeDuration(String purgeDuration) {
            if (purgeDuration == null) {
              throw new MissingRequiredPropertyException("GetNamespaceScheduledTaskAction", "purgeDuration");
            }
            this.purgeDuration = purgeDuration;
            return this;
        }
        @CustomType.Setter
        public Builder queryString(String queryString) {
            if (queryString == null) {
              throw new MissingRequiredPropertyException("GetNamespaceScheduledTaskAction", "queryString");
            }
            this.queryString = queryString;
            return this;
        }
        @CustomType.Setter
        public Builder savedSearchId(String savedSearchId) {
            if (savedSearchId == null) {
              throw new MissingRequiredPropertyException("GetNamespaceScheduledTaskAction", "savedSearchId");
            }
            this.savedSearchId = savedSearchId;
            return this;
        }
        @CustomType.Setter
        public Builder templateDetails(List<GetNamespaceScheduledTaskActionTemplateDetail> templateDetails) {
            if (templateDetails == null) {
              throw new MissingRequiredPropertyException("GetNamespaceScheduledTaskAction", "templateDetails");
            }
            this.templateDetails = templateDetails;
            return this;
        }
        public Builder templateDetails(GetNamespaceScheduledTaskActionTemplateDetail... templateDetails) {
            return templateDetails(List.of(templateDetails));
        }
        @CustomType.Setter
        public Builder type(String type) {
            if (type == null) {
              throw new MissingRequiredPropertyException("GetNamespaceScheduledTaskAction", "type");
            }
            this.type = type;
            return this;
        }
        public GetNamespaceScheduledTaskAction build() {
            final var _resultValue = new GetNamespaceScheduledTaskAction();
            _resultValue.compartmentIdInSubtree = compartmentIdInSubtree;
            _resultValue.dataType = dataType;
            _resultValue.metricExtractions = metricExtractions;
            _resultValue.purgeCompartmentId = purgeCompartmentId;
            _resultValue.purgeDuration = purgeDuration;
            _resultValue.queryString = queryString;
            _resultValue.savedSearchId = savedSearchId;
            _resultValue.templateDetails = templateDetails;
            _resultValue.type = type;
            return _resultValue;
        }
    }
}
