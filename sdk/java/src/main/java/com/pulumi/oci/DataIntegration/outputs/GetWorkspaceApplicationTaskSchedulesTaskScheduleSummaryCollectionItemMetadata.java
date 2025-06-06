// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataIntegration.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DataIntegration.outputs.GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItemMetadataAggregator;
import com.pulumi.oci.DataIntegration.outputs.GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItemMetadataCountStatistic;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItemMetadata {
    /**
     * @return The owning object key for this object.
     * 
     */
    private String aggregatorKey;
    /**
     * @return A summary type containing information about the object&#39;s aggregator including its type, key, name and description.
     * 
     */
    private List<GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItemMetadataAggregator> aggregators;
    /**
     * @return A count statistics.
     * 
     */
    private List<GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItemMetadataCountStatistic> countStatistics;
    /**
     * @return The user that created the object.
     * 
     */
    private String createdBy;
    /**
     * @return The user that created the object.
     * 
     */
    private String createdByName;
    /**
     * @return The full path to identify this object.
     * 
     */
    private String identifierPath;
    /**
     * @return Information property fields.
     * 
     */
    private Map<String,String> infoFields;
    /**
     * @return Specifies whether this object is a favorite or not.
     * 
     */
    private Boolean isFavorite;
    /**
     * @return Labels are keywords or tags that you can add to data assets, dataflows and so on. You can define your own labels and use them to categorize content.
     * 
     */
    private List<String> labels;
    /**
     * @return The registry version of the object.
     * 
     */
    private Integer registryVersion;
    /**
     * @return The date and time that the object was created.
     * 
     */
    private String timeCreated;
    /**
     * @return The date and time that the object was updated.
     * 
     */
    private String timeUpdated;
    /**
     * @return The user that updated the object.
     * 
     */
    private String updatedBy;
    /**
     * @return The user that updated the object.
     * 
     */
    private String updatedByName;

    private GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItemMetadata() {}
    /**
     * @return The owning object key for this object.
     * 
     */
    public String aggregatorKey() {
        return this.aggregatorKey;
    }
    /**
     * @return A summary type containing information about the object&#39;s aggregator including its type, key, name and description.
     * 
     */
    public List<GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItemMetadataAggregator> aggregators() {
        return this.aggregators;
    }
    /**
     * @return A count statistics.
     * 
     */
    public List<GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItemMetadataCountStatistic> countStatistics() {
        return this.countStatistics;
    }
    /**
     * @return The user that created the object.
     * 
     */
    public String createdBy() {
        return this.createdBy;
    }
    /**
     * @return The user that created the object.
     * 
     */
    public String createdByName() {
        return this.createdByName;
    }
    /**
     * @return The full path to identify this object.
     * 
     */
    public String identifierPath() {
        return this.identifierPath;
    }
    /**
     * @return Information property fields.
     * 
     */
    public Map<String,String> infoFields() {
        return this.infoFields;
    }
    /**
     * @return Specifies whether this object is a favorite or not.
     * 
     */
    public Boolean isFavorite() {
        return this.isFavorite;
    }
    /**
     * @return Labels are keywords or tags that you can add to data assets, dataflows and so on. You can define your own labels and use them to categorize content.
     * 
     */
    public List<String> labels() {
        return this.labels;
    }
    /**
     * @return The registry version of the object.
     * 
     */
    public Integer registryVersion() {
        return this.registryVersion;
    }
    /**
     * @return The date and time that the object was created.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The date and time that the object was updated.
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }
    /**
     * @return The user that updated the object.
     * 
     */
    public String updatedBy() {
        return this.updatedBy;
    }
    /**
     * @return The user that updated the object.
     * 
     */
    public String updatedByName() {
        return this.updatedByName;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItemMetadata defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String aggregatorKey;
        private List<GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItemMetadataAggregator> aggregators;
        private List<GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItemMetadataCountStatistic> countStatistics;
        private String createdBy;
        private String createdByName;
        private String identifierPath;
        private Map<String,String> infoFields;
        private Boolean isFavorite;
        private List<String> labels;
        private Integer registryVersion;
        private String timeCreated;
        private String timeUpdated;
        private String updatedBy;
        private String updatedByName;
        public Builder() {}
        public Builder(GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItemMetadata defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.aggregatorKey = defaults.aggregatorKey;
    	      this.aggregators = defaults.aggregators;
    	      this.countStatistics = defaults.countStatistics;
    	      this.createdBy = defaults.createdBy;
    	      this.createdByName = defaults.createdByName;
    	      this.identifierPath = defaults.identifierPath;
    	      this.infoFields = defaults.infoFields;
    	      this.isFavorite = defaults.isFavorite;
    	      this.labels = defaults.labels;
    	      this.registryVersion = defaults.registryVersion;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
    	      this.updatedBy = defaults.updatedBy;
    	      this.updatedByName = defaults.updatedByName;
        }

        @CustomType.Setter
        public Builder aggregatorKey(String aggregatorKey) {
            if (aggregatorKey == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItemMetadata", "aggregatorKey");
            }
            this.aggregatorKey = aggregatorKey;
            return this;
        }
        @CustomType.Setter
        public Builder aggregators(List<GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItemMetadataAggregator> aggregators) {
            if (aggregators == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItemMetadata", "aggregators");
            }
            this.aggregators = aggregators;
            return this;
        }
        public Builder aggregators(GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItemMetadataAggregator... aggregators) {
            return aggregators(List.of(aggregators));
        }
        @CustomType.Setter
        public Builder countStatistics(List<GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItemMetadataCountStatistic> countStatistics) {
            if (countStatistics == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItemMetadata", "countStatistics");
            }
            this.countStatistics = countStatistics;
            return this;
        }
        public Builder countStatistics(GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItemMetadataCountStatistic... countStatistics) {
            return countStatistics(List.of(countStatistics));
        }
        @CustomType.Setter
        public Builder createdBy(String createdBy) {
            if (createdBy == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItemMetadata", "createdBy");
            }
            this.createdBy = createdBy;
            return this;
        }
        @CustomType.Setter
        public Builder createdByName(String createdByName) {
            if (createdByName == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItemMetadata", "createdByName");
            }
            this.createdByName = createdByName;
            return this;
        }
        @CustomType.Setter
        public Builder identifierPath(String identifierPath) {
            if (identifierPath == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItemMetadata", "identifierPath");
            }
            this.identifierPath = identifierPath;
            return this;
        }
        @CustomType.Setter
        public Builder infoFields(Map<String,String> infoFields) {
            if (infoFields == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItemMetadata", "infoFields");
            }
            this.infoFields = infoFields;
            return this;
        }
        @CustomType.Setter
        public Builder isFavorite(Boolean isFavorite) {
            if (isFavorite == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItemMetadata", "isFavorite");
            }
            this.isFavorite = isFavorite;
            return this;
        }
        @CustomType.Setter
        public Builder labels(List<String> labels) {
            if (labels == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItemMetadata", "labels");
            }
            this.labels = labels;
            return this;
        }
        public Builder labels(String... labels) {
            return labels(List.of(labels));
        }
        @CustomType.Setter
        public Builder registryVersion(Integer registryVersion) {
            if (registryVersion == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItemMetadata", "registryVersion");
            }
            this.registryVersion = registryVersion;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItemMetadata", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(String timeUpdated) {
            if (timeUpdated == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItemMetadata", "timeUpdated");
            }
            this.timeUpdated = timeUpdated;
            return this;
        }
        @CustomType.Setter
        public Builder updatedBy(String updatedBy) {
            if (updatedBy == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItemMetadata", "updatedBy");
            }
            this.updatedBy = updatedBy;
            return this;
        }
        @CustomType.Setter
        public Builder updatedByName(String updatedByName) {
            if (updatedByName == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItemMetadata", "updatedByName");
            }
            this.updatedByName = updatedByName;
            return this;
        }
        public GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItemMetadata build() {
            final var _resultValue = new GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItemMetadata();
            _resultValue.aggregatorKey = aggregatorKey;
            _resultValue.aggregators = aggregators;
            _resultValue.countStatistics = countStatistics;
            _resultValue.createdBy = createdBy;
            _resultValue.createdByName = createdByName;
            _resultValue.identifierPath = identifierPath;
            _resultValue.infoFields = infoFields;
            _resultValue.isFavorite = isFavorite;
            _resultValue.labels = labels;
            _resultValue.registryVersion = registryVersion;
            _resultValue.timeCreated = timeCreated;
            _resultValue.timeUpdated = timeUpdated;
            _resultValue.updatedBy = updatedBy;
            _resultValue.updatedByName = updatedByName;
            return _resultValue;
        }
    }
}
