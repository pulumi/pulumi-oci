// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataScience.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetMlApplicationInstanceAuthConfiguration {
    /**
     * @return Name of the IDCS application
     * 
     */
    private String applicationName;
    /**
     * @return Identity Domain OCID
     * 
     */
    private String domainId;
    /**
     * @return Type of AuthN/Z
     * 
     */
    private String type;

    private GetMlApplicationInstanceAuthConfiguration() {}
    /**
     * @return Name of the IDCS application
     * 
     */
    public String applicationName() {
        return this.applicationName;
    }
    /**
     * @return Identity Domain OCID
     * 
     */
    public String domainId() {
        return this.domainId;
    }
    /**
     * @return Type of AuthN/Z
     * 
     */
    public String type() {
        return this.type;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetMlApplicationInstanceAuthConfiguration defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String applicationName;
        private String domainId;
        private String type;
        public Builder() {}
        public Builder(GetMlApplicationInstanceAuthConfiguration defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.applicationName = defaults.applicationName;
    	      this.domainId = defaults.domainId;
    	      this.type = defaults.type;
        }

        @CustomType.Setter
        public Builder applicationName(String applicationName) {
            if (applicationName == null) {
              throw new MissingRequiredPropertyException("GetMlApplicationInstanceAuthConfiguration", "applicationName");
            }
            this.applicationName = applicationName;
            return this;
        }
        @CustomType.Setter
        public Builder domainId(String domainId) {
            if (domainId == null) {
              throw new MissingRequiredPropertyException("GetMlApplicationInstanceAuthConfiguration", "domainId");
            }
            this.domainId = domainId;
            return this;
        }
        @CustomType.Setter
        public Builder type(String type) {
            if (type == null) {
              throw new MissingRequiredPropertyException("GetMlApplicationInstanceAuthConfiguration", "type");
            }
            this.type = type;
            return this;
        }
        public GetMlApplicationInstanceAuthConfiguration build() {
            final var _resultValue = new GetMlApplicationInstanceAuthConfiguration();
            _resultValue.applicationName = applicationName;
            _resultValue.domainId = domainId;
            _resultValue.type = type;
            return _resultValue;
        }
    }
}
