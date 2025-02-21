// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetAutonomousPatchResult {
    private String autonomousPatchId;
    /**
     * @return Maintenance run type, either &#34;QUARTERLY&#34; or &#34;TIMEZONE&#34;.
     * 
     */
    private String autonomousPatchType;
    /**
     * @return The text describing this patch package.
     * 
     */
    private String description;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return A descriptive text associated with the lifecycleState. Typically can contain additional displayable text.
     * 
     */
    private String lifecycleDetails;
    /**
     * @return Database patching model preference. See [My Oracle Support note 2285040.1](https://support.oracle.com/rs?type=doc&amp;id=2285040.1) for information on the Release Update (RU) and Release Update Revision (RUR) patching models.
     * 
     */
    private String patchModel;
    /**
     * @return First month of the quarter in which the patch was released.
     * 
     */
    private String quarter;
    /**
     * @return The current state of the patch as a result of lastAction.
     * 
     */
    private String state;
    /**
     * @return The date and time that the patch was released.
     * 
     */
    private String timeReleased;
    /**
     * @return The type of patch. BUNDLE is one example.
     * 
     */
    private String type;
    /**
     * @return The version of this patch package.
     * 
     */
    private String version;
    /**
     * @return Year in which the patch was released.
     * 
     */
    private String year;

    private GetAutonomousPatchResult() {}
    public String autonomousPatchId() {
        return this.autonomousPatchId;
    }
    /**
     * @return Maintenance run type, either &#34;QUARTERLY&#34; or &#34;TIMEZONE&#34;.
     * 
     */
    public String autonomousPatchType() {
        return this.autonomousPatchType;
    }
    /**
     * @return The text describing this patch package.
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return A descriptive text associated with the lifecycleState. Typically can contain additional displayable text.
     * 
     */
    public String lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * @return Database patching model preference. See [My Oracle Support note 2285040.1](https://support.oracle.com/rs?type=doc&amp;id=2285040.1) for information on the Release Update (RU) and Release Update Revision (RUR) patching models.
     * 
     */
    public String patchModel() {
        return this.patchModel;
    }
    /**
     * @return First month of the quarter in which the patch was released.
     * 
     */
    public String quarter() {
        return this.quarter;
    }
    /**
     * @return The current state of the patch as a result of lastAction.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return The date and time that the patch was released.
     * 
     */
    public String timeReleased() {
        return this.timeReleased;
    }
    /**
     * @return The type of patch. BUNDLE is one example.
     * 
     */
    public String type() {
        return this.type;
    }
    /**
     * @return The version of this patch package.
     * 
     */
    public String version() {
        return this.version;
    }
    /**
     * @return Year in which the patch was released.
     * 
     */
    public String year() {
        return this.year;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAutonomousPatchResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String autonomousPatchId;
        private String autonomousPatchType;
        private String description;
        private String id;
        private String lifecycleDetails;
        private String patchModel;
        private String quarter;
        private String state;
        private String timeReleased;
        private String type;
        private String version;
        private String year;
        public Builder() {}
        public Builder(GetAutonomousPatchResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.autonomousPatchId = defaults.autonomousPatchId;
    	      this.autonomousPatchType = defaults.autonomousPatchType;
    	      this.description = defaults.description;
    	      this.id = defaults.id;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.patchModel = defaults.patchModel;
    	      this.quarter = defaults.quarter;
    	      this.state = defaults.state;
    	      this.timeReleased = defaults.timeReleased;
    	      this.type = defaults.type;
    	      this.version = defaults.version;
    	      this.year = defaults.year;
        }

        @CustomType.Setter
        public Builder autonomousPatchId(String autonomousPatchId) {
            if (autonomousPatchId == null) {
              throw new MissingRequiredPropertyException("GetAutonomousPatchResult", "autonomousPatchId");
            }
            this.autonomousPatchId = autonomousPatchId;
            return this;
        }
        @CustomType.Setter
        public Builder autonomousPatchType(String autonomousPatchType) {
            if (autonomousPatchType == null) {
              throw new MissingRequiredPropertyException("GetAutonomousPatchResult", "autonomousPatchType");
            }
            this.autonomousPatchType = autonomousPatchType;
            return this;
        }
        @CustomType.Setter
        public Builder description(String description) {
            if (description == null) {
              throw new MissingRequiredPropertyException("GetAutonomousPatchResult", "description");
            }
            this.description = description;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetAutonomousPatchResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder lifecycleDetails(String lifecycleDetails) {
            if (lifecycleDetails == null) {
              throw new MissingRequiredPropertyException("GetAutonomousPatchResult", "lifecycleDetails");
            }
            this.lifecycleDetails = lifecycleDetails;
            return this;
        }
        @CustomType.Setter
        public Builder patchModel(String patchModel) {
            if (patchModel == null) {
              throw new MissingRequiredPropertyException("GetAutonomousPatchResult", "patchModel");
            }
            this.patchModel = patchModel;
            return this;
        }
        @CustomType.Setter
        public Builder quarter(String quarter) {
            if (quarter == null) {
              throw new MissingRequiredPropertyException("GetAutonomousPatchResult", "quarter");
            }
            this.quarter = quarter;
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetAutonomousPatchResult", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder timeReleased(String timeReleased) {
            if (timeReleased == null) {
              throw new MissingRequiredPropertyException("GetAutonomousPatchResult", "timeReleased");
            }
            this.timeReleased = timeReleased;
            return this;
        }
        @CustomType.Setter
        public Builder type(String type) {
            if (type == null) {
              throw new MissingRequiredPropertyException("GetAutonomousPatchResult", "type");
            }
            this.type = type;
            return this;
        }
        @CustomType.Setter
        public Builder version(String version) {
            if (version == null) {
              throw new MissingRequiredPropertyException("GetAutonomousPatchResult", "version");
            }
            this.version = version;
            return this;
        }
        @CustomType.Setter
        public Builder year(String year) {
            if (year == null) {
              throw new MissingRequiredPropertyException("GetAutonomousPatchResult", "year");
            }
            this.year = year;
            return this;
        }
        public GetAutonomousPatchResult build() {
            final var _resultValue = new GetAutonomousPatchResult();
            _resultValue.autonomousPatchId = autonomousPatchId;
            _resultValue.autonomousPatchType = autonomousPatchType;
            _resultValue.description = description;
            _resultValue.id = id;
            _resultValue.lifecycleDetails = lifecycleDetails;
            _resultValue.patchModel = patchModel;
            _resultValue.quarter = quarter;
            _resultValue.state = state;
            _resultValue.timeReleased = timeReleased;
            _resultValue.type = type;
            _resultValue.version = version;
            _resultValue.year = year;
            return _resultValue;
        }
    }
}
