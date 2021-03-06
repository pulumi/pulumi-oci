// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LogAnalytics.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetNamespaceScheduledTaskAction {
    /**
     * @return if true, purge child compartments data
     * 
     */
    private final Boolean compartmentIdInSubtree;
    /**
     * @return the type of the log data to be purged
     * 
     */
    private final String dataType;
    /**
     * @return the compartment OCID under which the data will be purged
     * 
     */
    private final String purgeCompartmentId;
    /**
     * @return The duration of data to be retained, which is used to calculate the timeDataEnded when the task fires. The value should be negative. Purge duration in ISO 8601 extended format as described in https://en.wikipedia.org/wiki/ISO_8601#Durations. The largest supported unit is D, e.g. -P365D (not -P1Y) or -P14D (not -P2W).
     * 
     */
    private final String purgeDuration;
    /**
     * @return Purge query string.
     * 
     */
    private final String queryString;
    /**
     * @return The ManagementSavedSearch id [OCID] utilized in the action.
     * 
     */
    private final String savedSearchId;
    /**
     * @return Schedule type discriminator.
     * 
     */
    private final String type;

    @CustomType.Constructor
    private GetNamespaceScheduledTaskAction(
        @CustomType.Parameter("compartmentIdInSubtree") Boolean compartmentIdInSubtree,
        @CustomType.Parameter("dataType") String dataType,
        @CustomType.Parameter("purgeCompartmentId") String purgeCompartmentId,
        @CustomType.Parameter("purgeDuration") String purgeDuration,
        @CustomType.Parameter("queryString") String queryString,
        @CustomType.Parameter("savedSearchId") String savedSearchId,
        @CustomType.Parameter("type") String type) {
        this.compartmentIdInSubtree = compartmentIdInSubtree;
        this.dataType = dataType;
        this.purgeCompartmentId = purgeCompartmentId;
        this.purgeDuration = purgeDuration;
        this.queryString = queryString;
        this.savedSearchId = savedSearchId;
        this.type = type;
    }

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

    public static final class Builder {
        private Boolean compartmentIdInSubtree;
        private String dataType;
        private String purgeCompartmentId;
        private String purgeDuration;
        private String queryString;
        private String savedSearchId;
        private String type;

        public Builder() {
    	      // Empty
        }

        public Builder(GetNamespaceScheduledTaskAction defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentIdInSubtree = defaults.compartmentIdInSubtree;
    	      this.dataType = defaults.dataType;
    	      this.purgeCompartmentId = defaults.purgeCompartmentId;
    	      this.purgeDuration = defaults.purgeDuration;
    	      this.queryString = defaults.queryString;
    	      this.savedSearchId = defaults.savedSearchId;
    	      this.type = defaults.type;
        }

        public Builder compartmentIdInSubtree(Boolean compartmentIdInSubtree) {
            this.compartmentIdInSubtree = Objects.requireNonNull(compartmentIdInSubtree);
            return this;
        }
        public Builder dataType(String dataType) {
            this.dataType = Objects.requireNonNull(dataType);
            return this;
        }
        public Builder purgeCompartmentId(String purgeCompartmentId) {
            this.purgeCompartmentId = Objects.requireNonNull(purgeCompartmentId);
            return this;
        }
        public Builder purgeDuration(String purgeDuration) {
            this.purgeDuration = Objects.requireNonNull(purgeDuration);
            return this;
        }
        public Builder queryString(String queryString) {
            this.queryString = Objects.requireNonNull(queryString);
            return this;
        }
        public Builder savedSearchId(String savedSearchId) {
            this.savedSearchId = Objects.requireNonNull(savedSearchId);
            return this;
        }
        public Builder type(String type) {
            this.type = Objects.requireNonNull(type);
            return this;
        }        public GetNamespaceScheduledTaskAction build() {
            return new GetNamespaceScheduledTaskAction(compartmentIdInSubtree, dataType, purgeCompartmentId, purgeDuration, queryString, savedSearchId, type);
        }
    }
}
