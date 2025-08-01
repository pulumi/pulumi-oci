// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetProvisionsProvisionCollectionItemTfOutput {
    /**
     * @return The indicator if the data for this parameter is sensitive (e.g. should the data be hidden in UI, encrypted if stored, etc.)
     * 
     */
    private Boolean isSensitive;
    /**
     * @return The output description
     * 
     */
    private String outputDescription;
    /**
     * @return The output name
     * 
     */
    private String outputName;
    /**
     * @return The output type
     * 
     */
    private String outputType;
    /**
     * @return The output value
     * 
     */
    private String outputValue;

    private GetProvisionsProvisionCollectionItemTfOutput() {}
    /**
     * @return The indicator if the data for this parameter is sensitive (e.g. should the data be hidden in UI, encrypted if stored, etc.)
     * 
     */
    public Boolean isSensitive() {
        return this.isSensitive;
    }
    /**
     * @return The output description
     * 
     */
    public String outputDescription() {
        return this.outputDescription;
    }
    /**
     * @return The output name
     * 
     */
    public String outputName() {
        return this.outputName;
    }
    /**
     * @return The output type
     * 
     */
    public String outputType() {
        return this.outputType;
    }
    /**
     * @return The output value
     * 
     */
    public String outputValue() {
        return this.outputValue;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetProvisionsProvisionCollectionItemTfOutput defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Boolean isSensitive;
        private String outputDescription;
        private String outputName;
        private String outputType;
        private String outputValue;
        public Builder() {}
        public Builder(GetProvisionsProvisionCollectionItemTfOutput defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.isSensitive = defaults.isSensitive;
    	      this.outputDescription = defaults.outputDescription;
    	      this.outputName = defaults.outputName;
    	      this.outputType = defaults.outputType;
    	      this.outputValue = defaults.outputValue;
        }

        @CustomType.Setter
        public Builder isSensitive(Boolean isSensitive) {
            if (isSensitive == null) {
              throw new MissingRequiredPropertyException("GetProvisionsProvisionCollectionItemTfOutput", "isSensitive");
            }
            this.isSensitive = isSensitive;
            return this;
        }
        @CustomType.Setter
        public Builder outputDescription(String outputDescription) {
            if (outputDescription == null) {
              throw new MissingRequiredPropertyException("GetProvisionsProvisionCollectionItemTfOutput", "outputDescription");
            }
            this.outputDescription = outputDescription;
            return this;
        }
        @CustomType.Setter
        public Builder outputName(String outputName) {
            if (outputName == null) {
              throw new MissingRequiredPropertyException("GetProvisionsProvisionCollectionItemTfOutput", "outputName");
            }
            this.outputName = outputName;
            return this;
        }
        @CustomType.Setter
        public Builder outputType(String outputType) {
            if (outputType == null) {
              throw new MissingRequiredPropertyException("GetProvisionsProvisionCollectionItemTfOutput", "outputType");
            }
            this.outputType = outputType;
            return this;
        }
        @CustomType.Setter
        public Builder outputValue(String outputValue) {
            if (outputValue == null) {
              throw new MissingRequiredPropertyException("GetProvisionsProvisionCollectionItemTfOutput", "outputValue");
            }
            this.outputValue = outputValue;
            return this;
        }
        public GetProvisionsProvisionCollectionItemTfOutput build() {
            final var _resultValue = new GetProvisionsProvisionCollectionItemTfOutput();
            _resultValue.isSensitive = isSensitive;
            _resultValue.outputDescription = outputDescription;
            _resultValue.outputName = outputName;
            _resultValue.outputType = outputType;
            _resultValue.outputValue = outputValue;
            return _resultValue;
        }
    }
}
