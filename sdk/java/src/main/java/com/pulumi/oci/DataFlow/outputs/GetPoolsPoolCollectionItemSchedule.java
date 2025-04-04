// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataFlow.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetPoolsPoolCollectionItemSchedule {
    /**
     * @return Day of the week SUN-SAT
     * 
     */
    private String dayOfWeek;
    /**
     * @return Hour of the day to start or stop pool.
     * 
     */
    private Integer startTime;
    /**
     * @return Hour of the day to stop the pool.
     * 
     */
    private Integer stopTime;

    private GetPoolsPoolCollectionItemSchedule() {}
    /**
     * @return Day of the week SUN-SAT
     * 
     */
    public String dayOfWeek() {
        return this.dayOfWeek;
    }
    /**
     * @return Hour of the day to start or stop pool.
     * 
     */
    public Integer startTime() {
        return this.startTime;
    }
    /**
     * @return Hour of the day to stop the pool.
     * 
     */
    public Integer stopTime() {
        return this.stopTime;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetPoolsPoolCollectionItemSchedule defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String dayOfWeek;
        private Integer startTime;
        private Integer stopTime;
        public Builder() {}
        public Builder(GetPoolsPoolCollectionItemSchedule defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.dayOfWeek = defaults.dayOfWeek;
    	      this.startTime = defaults.startTime;
    	      this.stopTime = defaults.stopTime;
        }

        @CustomType.Setter
        public Builder dayOfWeek(String dayOfWeek) {
            if (dayOfWeek == null) {
              throw new MissingRequiredPropertyException("GetPoolsPoolCollectionItemSchedule", "dayOfWeek");
            }
            this.dayOfWeek = dayOfWeek;
            return this;
        }
        @CustomType.Setter
        public Builder startTime(Integer startTime) {
            if (startTime == null) {
              throw new MissingRequiredPropertyException("GetPoolsPoolCollectionItemSchedule", "startTime");
            }
            this.startTime = startTime;
            return this;
        }
        @CustomType.Setter
        public Builder stopTime(Integer stopTime) {
            if (stopTime == null) {
              throw new MissingRequiredPropertyException("GetPoolsPoolCollectionItemSchedule", "stopTime");
            }
            this.stopTime = stopTime;
            return this;
        }
        public GetPoolsPoolCollectionItemSchedule build() {
            final var _resultValue = new GetPoolsPoolCollectionItemSchedule();
            _resultValue.dayOfWeek = dayOfWeek;
            _resultValue.startTime = startTime;
            _resultValue.stopTime = stopTime;
            return _resultValue;
        }
    }
}
