// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetRunbookVersionsRunbookVersionCollectionItemTaskStepPropertyPauseDetail {
    /**
     * @return Time in minutes to apply Pause.
     * 
     */
    private Integer durationInMinutes;
    /**
     * @return Run on based On.
     * 
     */
    private String kind;

    private GetRunbookVersionsRunbookVersionCollectionItemTaskStepPropertyPauseDetail() {}
    /**
     * @return Time in minutes to apply Pause.
     * 
     */
    public Integer durationInMinutes() {
        return this.durationInMinutes;
    }
    /**
     * @return Run on based On.
     * 
     */
    public String kind() {
        return this.kind;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetRunbookVersionsRunbookVersionCollectionItemTaskStepPropertyPauseDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Integer durationInMinutes;
        private String kind;
        public Builder() {}
        public Builder(GetRunbookVersionsRunbookVersionCollectionItemTaskStepPropertyPauseDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.durationInMinutes = defaults.durationInMinutes;
    	      this.kind = defaults.kind;
        }

        @CustomType.Setter
        public Builder durationInMinutes(Integer durationInMinutes) {
            if (durationInMinutes == null) {
              throw new MissingRequiredPropertyException("GetRunbookVersionsRunbookVersionCollectionItemTaskStepPropertyPauseDetail", "durationInMinutes");
            }
            this.durationInMinutes = durationInMinutes;
            return this;
        }
        @CustomType.Setter
        public Builder kind(String kind) {
            if (kind == null) {
              throw new MissingRequiredPropertyException("GetRunbookVersionsRunbookVersionCollectionItemTaskStepPropertyPauseDetail", "kind");
            }
            this.kind = kind;
            return this;
        }
        public GetRunbookVersionsRunbookVersionCollectionItemTaskStepPropertyPauseDetail build() {
            final var _resultValue = new GetRunbookVersionsRunbookVersionCollectionItemTaskStepPropertyPauseDetail();
            _resultValue.durationInMinutes = durationInMinutes;
            _resultValue.kind = kind;
            return _resultValue;
        }
    }
}
