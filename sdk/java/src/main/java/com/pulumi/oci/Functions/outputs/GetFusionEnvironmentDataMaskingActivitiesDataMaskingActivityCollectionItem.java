// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Functions.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetFusionEnvironmentDataMaskingActivitiesDataMaskingActivityCollectionItem {
    /**
     * @return unique FusionEnvironment identifier
     * 
     */
    private String fusionEnvironmentId;
    /**
     * @return Unique identifier that is immutable on creation.
     * 
     */
    private String id;
    private Boolean isResumeDataMasking;
    /**
     * @return A filter that returns all resources that match the specified status
     * 
     */
    private String state;
    /**
     * @return The time the data masking activity ended. An RFC3339 formatted datetime string.
     * 
     */
    private String timeMaskingFinish;
    /**
     * @return The time the data masking activity started. An RFC3339 formatted datetime string.
     * 
     */
    private String timeMaskingStart;

    private GetFusionEnvironmentDataMaskingActivitiesDataMaskingActivityCollectionItem() {}
    /**
     * @return unique FusionEnvironment identifier
     * 
     */
    public String fusionEnvironmentId() {
        return this.fusionEnvironmentId;
    }
    /**
     * @return Unique identifier that is immutable on creation.
     * 
     */
    public String id() {
        return this.id;
    }
    public Boolean isResumeDataMasking() {
        return this.isResumeDataMasking;
    }
    /**
     * @return A filter that returns all resources that match the specified status
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return The time the data masking activity ended. An RFC3339 formatted datetime string.
     * 
     */
    public String timeMaskingFinish() {
        return this.timeMaskingFinish;
    }
    /**
     * @return The time the data masking activity started. An RFC3339 formatted datetime string.
     * 
     */
    public String timeMaskingStart() {
        return this.timeMaskingStart;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetFusionEnvironmentDataMaskingActivitiesDataMaskingActivityCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String fusionEnvironmentId;
        private String id;
        private Boolean isResumeDataMasking;
        private String state;
        private String timeMaskingFinish;
        private String timeMaskingStart;
        public Builder() {}
        public Builder(GetFusionEnvironmentDataMaskingActivitiesDataMaskingActivityCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.fusionEnvironmentId = defaults.fusionEnvironmentId;
    	      this.id = defaults.id;
    	      this.isResumeDataMasking = defaults.isResumeDataMasking;
    	      this.state = defaults.state;
    	      this.timeMaskingFinish = defaults.timeMaskingFinish;
    	      this.timeMaskingStart = defaults.timeMaskingStart;
        }

        @CustomType.Setter
        public Builder fusionEnvironmentId(String fusionEnvironmentId) {
            this.fusionEnvironmentId = Objects.requireNonNull(fusionEnvironmentId);
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder isResumeDataMasking(Boolean isResumeDataMasking) {
            this.isResumeDataMasking = Objects.requireNonNull(isResumeDataMasking);
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }
        @CustomType.Setter
        public Builder timeMaskingFinish(String timeMaskingFinish) {
            this.timeMaskingFinish = Objects.requireNonNull(timeMaskingFinish);
            return this;
        }
        @CustomType.Setter
        public Builder timeMaskingStart(String timeMaskingStart) {
            this.timeMaskingStart = Objects.requireNonNull(timeMaskingStart);
            return this;
        }
        public GetFusionEnvironmentDataMaskingActivitiesDataMaskingActivityCollectionItem build() {
            final var o = new GetFusionEnvironmentDataMaskingActivitiesDataMaskingActivityCollectionItem();
            o.fusionEnvironmentId = fusionEnvironmentId;
            o.id = id;
            o.isResumeDataMasking = isResumeDataMasking;
            o.state = state;
            o.timeMaskingFinish = timeMaskingFinish;
            o.timeMaskingStart = timeMaskingStart;
            return o;
        }
    }
}