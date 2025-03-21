// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Optimizer.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Optimizer.outputs.GetProfileLevelsProfileLevelCollectionItemMetric;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetProfileLevelsProfileLevelCollectionItem {
    /**
     * @return The default aggregation interval (in days) for profiles using this profile level.
     * 
     */
    private Integer defaultInterval;
    /**
     * @return The metrics that will be evaluated by profiles using this profile level.
     * 
     */
    private List<GetProfileLevelsProfileLevelCollectionItemMetric> metrics;
    /**
     * @return Optional. A filter that returns results that match the name specified.
     * 
     */
    private String name;
    /**
     * @return Optional. A filter that returns results that match the recommendation name specified.
     * 
     */
    private String recommendationName;
    /**
     * @return The date and time the category details were created, in the format defined by RFC3339.
     * 
     */
    private String timeCreated;
    /**
     * @return The date and time the category details were last updated, in the format defined by RFC3339.
     * 
     */
    private String timeUpdated;
    /**
     * @return An array of aggregation intervals (in days) allowed for profiles using this profile level.
     * 
     */
    private List<Integer> validIntervals;

    private GetProfileLevelsProfileLevelCollectionItem() {}
    /**
     * @return The default aggregation interval (in days) for profiles using this profile level.
     * 
     */
    public Integer defaultInterval() {
        return this.defaultInterval;
    }
    /**
     * @return The metrics that will be evaluated by profiles using this profile level.
     * 
     */
    public List<GetProfileLevelsProfileLevelCollectionItemMetric> metrics() {
        return this.metrics;
    }
    /**
     * @return Optional. A filter that returns results that match the name specified.
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return Optional. A filter that returns results that match the recommendation name specified.
     * 
     */
    public String recommendationName() {
        return this.recommendationName;
    }
    /**
     * @return The date and time the category details were created, in the format defined by RFC3339.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The date and time the category details were last updated, in the format defined by RFC3339.
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }
    /**
     * @return An array of aggregation intervals (in days) allowed for profiles using this profile level.
     * 
     */
    public List<Integer> validIntervals() {
        return this.validIntervals;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetProfileLevelsProfileLevelCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Integer defaultInterval;
        private List<GetProfileLevelsProfileLevelCollectionItemMetric> metrics;
        private String name;
        private String recommendationName;
        private String timeCreated;
        private String timeUpdated;
        private List<Integer> validIntervals;
        public Builder() {}
        public Builder(GetProfileLevelsProfileLevelCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.defaultInterval = defaults.defaultInterval;
    	      this.metrics = defaults.metrics;
    	      this.name = defaults.name;
    	      this.recommendationName = defaults.recommendationName;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
    	      this.validIntervals = defaults.validIntervals;
        }

        @CustomType.Setter
        public Builder defaultInterval(Integer defaultInterval) {
            if (defaultInterval == null) {
              throw new MissingRequiredPropertyException("GetProfileLevelsProfileLevelCollectionItem", "defaultInterval");
            }
            this.defaultInterval = defaultInterval;
            return this;
        }
        @CustomType.Setter
        public Builder metrics(List<GetProfileLevelsProfileLevelCollectionItemMetric> metrics) {
            if (metrics == null) {
              throw new MissingRequiredPropertyException("GetProfileLevelsProfileLevelCollectionItem", "metrics");
            }
            this.metrics = metrics;
            return this;
        }
        public Builder metrics(GetProfileLevelsProfileLevelCollectionItemMetric... metrics) {
            return metrics(List.of(metrics));
        }
        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("GetProfileLevelsProfileLevelCollectionItem", "name");
            }
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder recommendationName(String recommendationName) {
            if (recommendationName == null) {
              throw new MissingRequiredPropertyException("GetProfileLevelsProfileLevelCollectionItem", "recommendationName");
            }
            this.recommendationName = recommendationName;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetProfileLevelsProfileLevelCollectionItem", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(String timeUpdated) {
            if (timeUpdated == null) {
              throw new MissingRequiredPropertyException("GetProfileLevelsProfileLevelCollectionItem", "timeUpdated");
            }
            this.timeUpdated = timeUpdated;
            return this;
        }
        @CustomType.Setter
        public Builder validIntervals(List<Integer> validIntervals) {
            if (validIntervals == null) {
              throw new MissingRequiredPropertyException("GetProfileLevelsProfileLevelCollectionItem", "validIntervals");
            }
            this.validIntervals = validIntervals;
            return this;
        }
        public Builder validIntervals(Integer... validIntervals) {
            return validIntervals(List.of(validIntervals));
        }
        public GetProfileLevelsProfileLevelCollectionItem build() {
            final var _resultValue = new GetProfileLevelsProfileLevelCollectionItem();
            _resultValue.defaultInterval = defaultInterval;
            _resultValue.metrics = metrics;
            _resultValue.name = name;
            _resultValue.recommendationName = recommendationName;
            _resultValue.timeCreated = timeCreated;
            _resultValue.timeUpdated = timeUpdated;
            _resultValue.validIntervals = validIntervals;
            return _resultValue;
        }
    }
}
